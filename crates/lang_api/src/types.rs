//! Shared declaration + import types used by adapters.
//!
//! These types are the contract between adapters and the core engine. Keep
//! them minimal: every field costs every adapter.

use ahash::AHashMap;
use bonsai_common::{FileId, Precision, Span, SymbolId};
use serde::{Deserialize, Serialize};

/// Short lowercase language identifier (e.g. `"rust"`, `"python"`).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct LanguageId(pub &'static str);

impl LanguageId {
    #[must_use]
    pub const fn new(s: &'static str) -> Self {
        Self(s)
    }
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// A logical workspace root (package, crate, module root, ...).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRoot {
    pub name: String,
    pub files: Vec<FileId>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
    Crate,
    Module,
    Protected,
    Internal,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclKind {
    Module,
    Namespace,
    Function,
    Method,
    Constructor,
    Class,
    Struct,
    Trait,
    Interface,
    Enum,
    EnumVariant,
    TypeAlias,
    Global,
    Const,
    Static,
    Import,
    Field,
    Other,
}

/// Adapter-supplied module / package / crate boundary used for
/// `Visibility::Module` and `Visibility::Crate` filtering in the
/// resolver. Segments are language-specific:
///
/// - Java / Kotlin / Scala: package segments (`com.foo.bar` → `["com", "foo", "bar"]`).
/// - Rust: crate name + mod path (`mycrate::a::b` → `["mycrate", "a", "b"]`).
/// - Go / Python: package / module dotted path.
/// - C / C++: file stem when no language-level module boundary exists.
/// - JS / TS: module = file path relative to repo root.
/// - PHP: namespace segments.
/// - Lua / Bash: file stem.
///
/// Empty (`segments.is_empty()`) means "no module boundary applicable"
/// — the resolver treats `Module` visibility as file-scoped in that
/// case. Adapters should populate this in lockstep with
/// `Decl.qualified_name` and `Decl.visibility`. See
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModulePath {
    pub segments: Vec<String>,
}

impl ModulePath {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_segments<I, S>(segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            segments: segments.into_iter().map(Into::into).collect(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns true when `self` and `other` declare the same package /
    /// module / crate boundary. Empty segments are treated as a
    /// language-specific "no module" sentinel and never match a
    /// non-empty path.
    #[must_use]
    pub fn matches(&self, other: &ModulePath) -> bool {
        !self.segments.is_empty() && self.segments == other.segments
    }

    /// Returns true when `self` shares the top-level segment of
    /// `other`. Used for `Visibility::Crate` filtering — Rust
    /// `pub(crate)` decls are visible across the same crate.
    #[must_use]
    pub fn shares_top_segment(&self, other: &ModulePath) -> bool {
        match (self.segments.first(), other.segments.first()) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

/// A single declaration in a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decl {
    pub symbol: SymbolId,
    pub kind: DeclKind,
    pub name: String,
    pub qualified_name: Option<String>,
    /// Adapter-supplied module / package / crate boundary. See
    /// [`ModulePath`] for per-language conventions. Used by the
    /// resolver to filter `Visibility::Module` and
    /// `Visibility::Crate` candidates by caller-module context.
    /// Empty until the per-language adapter populates this; the
    /// resolver treats empty as "file-scoped only" until then.
    #[serde(default, skip_serializing_if = "ModulePath::is_empty")]
    pub module_path: ModulePath,
    pub span: Span,
    pub name_span: Span,
    pub visibility: Visibility,
    pub parent: Option<SymbolId>,
    /// If this decl is a function, points at its HIR-ready body span.
    pub body_span: Option<Span>,
    /// Structured control-flow events inside this decl's body. Empty for
    /// non-function decls. Populated by adapters using the grammar-driven
    /// walker in `kit::walk_flow_events` (or hand-rolled).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_events: Vec<FlowEvent>,
    /// True when this declaration belongs to a language/body form where
    /// the final expression can be returned without an explicit return
    /// keyword. Adapters set this from grammar semantics; analyses must
    /// not infer it from declaration names or language strings.
    #[serde(default)]
    pub has_implicit_returns: bool,
    /// Parameter names, in order. Lets the tracer bind call-site arguments
    /// to parameter names for higher-order callback resolution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    /// Parameter annotations / decorators, parallel-indexed with
    /// `params`. Each inner `Vec<String>` is the list of annotation /
    /// decorator names attached to the corresponding parameter
    /// (e.g. `["RequestParam"]` for Spring's `@RequestParam String x`).
    /// Empty for parameters without annotations and for adapters that
    /// don't surface this information. Adapter facts only — the engine
    /// does not interpret these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_annotations: Vec<Vec<String>>,
    /// Adapter-derived local/parameter/field receiver type bindings
    /// valid inside this declaration. This is syntax metadata from
    /// parsed declarations, used by matchers to resolve
    /// `receiver.method()` against rules written as `[Type, method]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_aliases: Vec<TypeAliasBinding>,
    /// Adapter-derived superclass / interface / mixin / trait names
    /// for class-like decls. Each entry is the bare type identifier
    /// the source declaration listed (`class Echo extends WebSocketHandler` →
    /// `["WebSocketHandler"]`; Python `class Echo(WebSocketHandler, Mixin):`
    /// → `["WebSocketHandler", "Mixin"]`; Java `class C extends B implements I`
    /// → `["B", "I"]`). Generic / qualified bases collapse to the bare
    /// type tail. The matcher consults this list when a `kind: param`
    /// rule's `in_class:` constraint names an ancestor type that the
    /// user's class extends rather than the user's class itself —
    /// makes `WebSocketHandler.on_message` rules match real subclass
    /// methods per docs/contributing/design-patterns.mdx::Semantic Resolution Always.
    /// Empty for non-class decls and for adapters that don't yet
    /// expose inheritance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<String>,
    /// Index into `params` for a grammar-declared receiver binding when
    /// the language exposes one as a normal parameter. This is adapter
    /// metadata, not a name convention: consumers must not infer receivers
    /// by checking for strings such as `self` or `this`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_param_index: Option<usize>,
    /// Adapter-derived receiver-field writes inside this declaration.
    /// These are emitted from parsed assignment structure and parameter
    /// metadata so downstream analyses do not need to guess receiver
    /// names or parse target syntax.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_field_writes: Vec<FieldWrite>,
    /// Adapter-declared receiver aliases that are valid inside this
    /// declaration when the language has an implicit receiver. Examples
    /// include the grammar tokens for current/super receiver forms. This
    /// is syntax metadata from the adapter, not a taint-engine name guess.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implicit_receiver_names: Vec<String>,
    /// Adapter-derived source operands that read from implicit receiver
    /// state inside this declaration. When a call arrives through a tainted
    /// receiver, these names are seeded so normal assignment/call transfer
    /// can follow receiver-field/property reads without engine string hacks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_state_sources: Vec<String>,
    /// Adapter-extracted return type for function-shaped decls.
    /// Populated when the source has an explicit return-type
    /// annotation (Python `-> T`, TypeScript `: T`, Rust `-> T`,
    /// Java/C# return type, Kotlin `: T`, Swift `-> T`, Go return
    /// type, Scala `: T`). Empty for
    /// languages without explicit return types or when the
    /// adapter hasn't been updated. The `apply_assign_call_result_types`
    /// pass uses this to propagate the type onto the LHS of
    /// `let y = f()` so subsequent `y.method()` calls resolve
    /// against `T`'s methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    /// True when the final declared parameter is a positional variadic
    /// collector (`*args`, `...rest`, `T...`, C `...`) that absorbs all
    /// overflow positional arguments. Adapter / kit fact: named splats are
    /// still stored under their bare name in `params`, so the engine needs
    /// this explicit signal to route every extra positional arg onto the
    /// collector param instead of dropping it (audit M1). Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_variadic: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeAliasBinding {
    pub name: String,
    pub type_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldWrite {
    pub span: Span,
    /// Adapter-normalized field/container place, e.g. `self.cmd` or
    /// `env.cmd`. This is a stable place key, not a parsing surface.
    pub target: String,
    /// Parameter indices whose values feed this field write. Receiver
    /// parameters are excluded by the adapter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_param_indices: Vec<usize>,
}

/// AST-derived value dependencies for a return/yield expression.
///
/// Adapters build this from tree-sitter nodes. Core engines consume these
/// facts directly and must never recover them by tokenizing `value_text`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressionFlow {
    /// Exact addressable value place when the whole expression is a place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// Structured projection for an exact field/subscript place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<ExpressionProjection>,
    /// AST-proven value operands in a compound scalar expression. Callee
    /// names and method receivers are excluded; nested calls are represented
    /// by `call_sites` and ordinary `FlowEvent::Call` records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
    /// Nested call-expression spans whose results contribute to this value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_sites: Vec<Span>,
    /// Statically named record/map/object fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregate_fields: Vec<ExpressionField>,
    /// Positional tuple/list/array items, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tuple_items: Vec<ExpressionFlow>,
    /// Struct/map/object spread operands, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spreads: Vec<ExpressionFlow>,
}

impl ExpressionFlow {
    #[must_use]
    pub fn from_place(place: impl Into<String>) -> Self {
        let place = place.into();
        let place = place.trim().to_string();
        if place.is_empty() {
            return Self::default();
        }
        Self {
            projection: ExpressionProjection::from_adapter_place(&place),
            source_names: vec![place.clone()],
            place: Some(place),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn from_source_names(source_names: Vec<String>) -> Self {
        Self {
            source_names,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.place.is_none()
            && self.projection.is_none()
            && self.source_names.is_empty()
            && self.call_sites.is_empty()
            && self.aggregate_fields.is_empty()
            && self.tuple_items.is_empty()
            && self.spreads.is_empty()
    }
}

/// Adapter-normalized exact projection (`base.field.subfield`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressionProjection {
    pub base: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
}

impl ExpressionProjection {
    /// Construct from an adapter-proven canonical place. This helper is for
    /// synthetic adapter facts; raw source text must not be passed here.
    #[must_use]
    pub fn from_adapter_place(place: &str) -> Option<Self> {
        let mut parts = place.split('.').map(str::trim).filter(|part| !part.is_empty());
        let base = parts.next()?.to_string();
        let path: Vec<String> = parts.map(ToString::to_string).collect();
        (!path.is_empty()).then_some(Self { base, path })
    }

    /// Render the adapter-normalized projection as its canonical place key.
    /// This is a structured-fact renderer, not a source-text parser.
    #[must_use]
    pub fn canonical_place(&self) -> String {
        std::iter::once(self.base.as_str())
            .chain(self.path.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// One statically named aggregate field and its structured value flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressionField {
    pub name: String,
    /// Exact parsed value-expression for this field. Frontends preserve this
    /// span so consumers can join nested aggregate flow to other typed facts
    /// without recovering field boundaries from rendered source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_span: Option<Span>,
    pub value: ExpressionFlow,
}

/// Ordered fields of an aggregate type as declared by the grammar.
///
/// Positional aggregate initializers (for example C++ `T{x, y}`) are
/// resolved against these facts by the workspace semantic pass. Keeping the
/// declaration order explicit avoids source-name inventories and prevents a
/// whole-object assignment from being fanned out to unrelated fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateLayout {
    pub type_name: String,
    pub fields: Vec<String>,
}

/// One piece of control flow inside a function body. Kept as a tree so the
/// cross-module tracer can walk branches and loops with real structure
/// rather than a flat sequence of call sites.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowEvent {
    Call {
        span: Span,
        name: String,
        /// Adapter-normalized receiver/base expression for method
        /// calls, when the parsed call syntax exposes one. Consumers
        /// must use this field instead of splitting `name`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receiver: Option<String>,
        /// Adapter/index-derived static receiver types for the receiver
        /// expression. This is a semantic fact derived from
        /// `Decl.type_aliases` and class ancestry, not a receiver-name
        /// heuristic. Consumers should prefer it before falling back to
        /// textual receiver inference.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        receiver_types: Vec<String>,
        call_kind: CallKind,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<CallArg>,
    },
    Branch {
        span: Span,
        /// Normalized source text retained for diagnostics and rendering.
        /// Semantic consumers use the adapter-lowered
        /// [`BranchConditionFact`] for this span and must not parse this
        /// string to recover language operators or runtime meaning.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        then_events: Vec<FlowEvent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        else_events: Vec<FlowEvent>,
    },
    Loop {
        span: Span,
        loop_kind: LoopKind,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        body: Vec<FlowEvent>,
    },
    Assign {
        span: Span,
        target: String,
        /// Bare-identifier RHS, when the adapter can prove the RHS is
        /// a simple name reference (`y = x` → `source_name = Some("x")`).
        /// For compound expressions / call RHS / field access the
        /// adapter leaves this `None` and the richer signal lives in
        /// `source_call` (for call RHS) or in the neighbouring events.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_name: Option<String>,
        /// The RHS, when it is a direct call / construction / member-
        /// call expression. Adapters populate this with the callee's
        /// short name (`f` for `y = f(x)`, `read` for `y = db.read(x)`).
        /// Lets the interprocedural taint pass propagate return-value
        /// taint: `y = transform(x)` taints `y` iff `transform`'s
        /// summary says param 0 transits to return AND `x` is tainted
        /// at the call site. Without this signal, adapters emit both
        /// an `Assign { source_name: None }` and a sibling
        /// `Call { name: "transform" }` — the binding between the two
        /// is lost by the time the inter pass sees them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_call: Option<String>,
        /// When `source_call` is set, the argument values at the call
        /// site (for matching against the callee's summary). Each
        /// entry is the caller's source-level text for that
        /// positional argument — typically a bare identifier
        /// (`x`, `user_input`, …) that the interprocedural pass can
        /// look up in the caller's current taint state.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        source_call_args: Vec<String>,
        /// Every bare-identifier name that appears in the RHS
        /// expression, when the RHS is compound (concat, arithmetic,
        /// ternary, member access, subscript, template literal, etc).
        /// `y = x + prefix` → `source_names: ["x", "prefix"]`;
        /// `y = obj.field` → `source_names: ["obj"]`;
        /// `y = f"{cmd} {flag}"` → `source_names: ["cmd", "flag"]`.
        /// Empty when the adapter uses `source_name` (simple rename)
        /// or `source_call` (direct call RHS). Read by the intra/
        /// inter passes to propagate taint through compound
        /// expressions without requiring explicit AST evaluation.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        source_names: Vec<String>,
        /// True when this assignment is a new local binding
        /// (`let`/`var`/`val`/`const`/`my`/`our`/`local`/Python
        /// first-assignment, etc.). Phase-2 scope-aware bindings
        /// uses this to detect shadowing — a `let x` inside a
        /// nested block introduces a fresh name binding rather
        /// than mutating an outer `x`. Adapters set this when the
        /// CST node-kind is unambiguously a declaration; for
        /// re-assignments (`x = …` without a declaration keyword)
        /// the field stays `false`. Default `false` keeps
        /// pre-Phase-2 behaviour for adapters that haven't been
        /// updated yet.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        declares_new_binding: bool,
        /// Optional shape classification of the RHS for
        /// Phase-5 constant-propagation. `None` keeps prior
        /// behaviour (engine treats the RHS as `Unknown`).
        /// `Some(AssignValueKind::Literal)` lets the transfer
        /// pass skip name-bridging because the RHS doesn't
        /// reference any tainted carrier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_kind: Option<AssignValueKind>,
    },
    /// A positional or named aggregate initializer lowered from its parsed
    /// expression node. `value_flow.tuple_items` preserves source order until
    /// the workspace resolves it against an [`AggregateLayout`]; named
    /// initializers arrive directly in `value_flow.aggregate_fields`.
    AggregateAssign {
        span: Span,
        target: String,
        /// Adapter-normalized declared type of `target`, when syntax exposes
        /// it. This is a type identity, never an API/name heuristic.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_name: Option<String>,
        #[serde(default, skip_serializing_if = "ExpressionFlow::is_empty")]
        value_flow: ExpressionFlow,
    },
    Return {
        span: Span,
        /// Verbatim return expression text when available. Used by
        /// semantic taint summaries for compound returns such as
        /// `return {"cmd": v}` or `return f"{x}"`, where no single
        /// bare `value_name` exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_text: Option<String>,
        /// Single value-bearing identifier returned, when the adapter
        /// can determine it precisely. `return x` and
        /// ``return `${x}``` both produce `Some("x")`; multi-source
        /// expressions such as `return x + y` stay `None`. Used by
        /// the interprocedural summary to compute return taint without
        /// treating static literal text as a value read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_name: Option<String>,
        /// Compiler facts derived from the return expression's tree-sitter
        /// node. `value_text` above is rendering-only.
        #[serde(default, skip_serializing_if = "ExpressionFlow::is_empty")]
        value_flow: ExpressionFlow,
    },
    Throw {
        span: Span,
        /// The bare-identifier name of the value being thrown, when
        /// the adapter can determine it. `throw err` →
        /// `value_name: Some("err")`. `None` for compound throw
        /// expressions. Used by G8 to link a thrown tainted value to
        /// the catching handler's binding parameter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_name: Option<String>,
        /// The static type of the thrown value, when the adapter can
        /// determine it from syntax. Java `throw new IOException(...)`
        /// → `Some("IOException")`. Kotlin `throw IOException()` →
        /// `Some("IOException")`. C# `throw new IOException(...)` →
        /// `Some("IOException")`. The engine pairs this with
        /// `Try::catch_types` to skip seeding catch arms whose declared
        /// type can't catch this throw. `None` for adapters that
        /// don't surface throw types yet (the engine then falls back
        /// to the conservative "seed if any taint is thrown" rule).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        thrown_type: Option<String>,
    },
    /// Exception-handling region. `body` is the try / begin block;
    /// `catch_events` merges every catch / except / rescue arm into a
    /// single flat list; `finally_events` holds the ensure / finally
    /// block. `catch_param` is the first-parameter binding of the
    /// catch clause — `e` in `catch (e)` / `except Exception as e:` /
    /// `rescue => e`. When present, G8 seeds the catch region with
    /// this name pre-tainted whenever any Throw in the body throws a
    /// tainted value_name.
    Try {
        span: Span,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        body: Vec<FlowEvent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        catch_events: Vec<FlowEvent>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        finally_events: Vec<FlowEvent>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        catch_param: Option<String>,
        /// Union of declared catch-arm types across every arm of this
        /// try. Java `catch (IOException e)` →
        /// `["IOException"]`; multiple arms `catch (A | B e) { } catch
        /// (C e) { }` → `["A", "B", "C"]`. Empty for adapters that
        /// don't surface types or for catch-all arms (`catch (...)`,
        /// `except:`). When non-empty, the engine pairs this with
        /// `Throw::thrown_type` to seed the catch param only when at
        /// least one body throw is type-assignable. Kept as `Vec` not
        /// `BTreeSet` so the order traces back to source order (debug
        /// readability) — duplicates are fine.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        catch_types: Vec<String>,
    },
    /// `break`, `next`, `redo`, `retry` or a labeled variant — a
    /// terminating edge inside the enclosing loop/block.
    Break {
        span: Span,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// `continue` or the equivalent skip-to-next-iteration form.
    Continue {
        span: Span,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// `yield` / `yield from` — a suspend-and-emit edge. Tracked with the
    /// yielded expression as text so consumers can show the flow.
    Yield {
        span: Span,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_text: Option<String>,
        /// Compiler facts derived from the yielded expression node.
        #[serde(default, skip_serializing_if = "ExpressionFlow::is_empty")]
        value_flow: ExpressionFlow,
    },
    /// `await` / `.await` / `await?`. Awaits are frequently the point
    /// where an async function re-enters the scheduler — worth surfacing
    /// alongside calls rather than being folded into them. `value_name`
    /// captures the bare identifier being awaited (`await promise` →
    /// `Some("promise")`); `None` for compound awaited expressions
    /// (`await f(x)`). The intra-pass uses this to propagate taint
    /// across the await boundary — an awaited tainted promise yields
    /// a tainted resolved value.
    Await {
        span: Span,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_name: Option<String>,
    },
    /// Go's `defer stmt` / Swift's `defer { ... }`. Recorded as a
    /// deferred statement whose events run on scope exit.
    Defer {
        span: Span,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        body: Vec<FlowEvent>,
    },
    /// `with` (Python) / `using` (C#) context-manager scope. The body
    /// holds the events that run under the managed resource.
    Using {
        span: Span,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        body: Vec<FlowEvent>,
    },
    /// Resource lifecycle transition (free / close / unlock /
    /// cancel / move) on a named binding. Consumed by the matcher's
    /// `RequiresState` constraint. `name` is the bare binding;
    /// `transition` is one of the canonical states (`freed`,
    /// `closed`, `unlocked`, `cancelled`, `moved`).
    Lifecycle {
        span: Span,
        name: String,
        transition: String,
    },
}

/// Independently decodable syntax targets projected from one compiler object.
///
/// This is a scheduling header, not a second semantic representation. It is
/// derived only from [`DeclIndex`] facts emitted by the owning language
/// adapter and lets broad consumers reject files that cannot contain a
/// requested call before inflating declaration bodies and flow events.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerSyntaxHeader {
    /// Every adapter-emitted call shape in the file. Spans and arguments stay
    /// in the compiler-object body because they are needed only after a rule
    /// target has selected the file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CompilerCallHeader>,
    /// Exact assignment aliases (`target = source`) from the adapter's flow
    /// tree. Consumers may use these to extend import aliases to a fixed point
    /// before deciding that a call target is impossible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignment_aliases: Vec<CompilerAssignmentAlias>,
    /// Direct call-result assignments used by rulepack-declared factory
    /// return typing. The call/receiver identities come from adapter facts,
    /// never from parsing assignment text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factory_assignments: Vec<CompilerFactoryCallAssignment>,
    /// Adapter-derived type aliases visible somewhere in the file. This is an
    /// intentional over-approximation for header planning; declaration-local
    /// scope and ordering remain enforced by the full matcher body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_aliases: Vec<TypeAliasBinding>,
}

/// Independently decodable browse/search terms projected from one compiler
/// object.
///
/// This is an exact projection of adapter-lowered declarations, references,
/// imports, literals, comments, and flow events. It is persisted separately
/// from both syntax-target headers and full bodies so broad candidate-index
/// construction never has to inflate dataflow IR. Terms are normalized once
/// while the canonical compiler object is resident; consumers may narrow
/// candidate files with them, but must hydrate rendered facts through the
/// canonical APIs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerBrowseHeader {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CompilerBrowseTermGroup>,
}

/// Sorted normalized terms for one browse fact kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerBrowseTermGroup {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terms: Vec<String>,
}

/// Compact call target retained in [`CompilerSyntaxHeader`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerCallHeader {
    pub name: String,
    /// Adapter-normalized receiver/base expression when the call event
    /// provides one. No consumer may reconstruct this from source text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_types: Vec<String>,
    pub call_kind: CallKind,
}

/// One adapter-proven assignment alias retained in a syntax header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerAssignmentAlias {
    pub target: String,
    pub source: String,
}

/// One direct call-result assignment retained for factory-return typing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerFactoryCallAssignment {
    pub target: String,
    pub call_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_receiver: Option<String>,
}

/// Independently decodable call/write attribution projected from one exact
/// compiler object.
///
/// This is not a second lowering path. Every field comes directly from the
/// owning adapter's [`DeclIndex`] / [`FlowEvent`] IR and is persisted beside
/// the full body so path rendering can open only the facts it consumes. The
/// declaration span is the relocatable identity: workspace linking remaps
/// symbols, while source spans remain stable inside the content-addressed
/// object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerAttribution {
    pub file: FileId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<CompilerFunctionAttribution>,
}

/// Compact attribution for one function-shaped declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerFunctionAttribution {
    pub declaration_span: Span,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CompilerCallAttribution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub return_spans: Vec<Span>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<CompilerWriteAttribution>,
}

/// One adapter-lowered call site needed to reconstruct exact taint evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerCallAttribution {
    pub span: Span,
    pub name: String,
    pub call_kind: CallKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<CompilerCallArgumentAttribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    /// Value carriers from the adapter's structured receiver expression.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_source_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_types: Vec<String>,
}

/// The rendering and AST-derived carrier facts for one call argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerCallArgumentAttribution {
    pub span: Span,
    pub value_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
}

/// One exact assignment-shaped write and its adapter-proven RHS carriers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerWriteAttribution {
    pub span: Span,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
}

impl CompilerAttribution {
    /// Project call, return, and write evidence from canonical adapter IR.
    #[must_use]
    pub fn from_decl_index(index: &DeclIndex) -> Self {
        fn is_bare_identifier(text: &str) -> bool {
            let mut chars = text.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
        }

        fn collect_expression_carriers(flow: &ExpressionFlow, out: &mut ahash::AHashSet<String>) {
            if let Some(place) = flow.place.as_deref() {
                let place = place.trim();
                if !place.is_empty() {
                    out.insert(place.to_string());
                }
            }
            for source in &flow.source_names {
                let source = source.trim();
                if !source.is_empty() {
                    out.insert(source.to_string());
                }
            }
            for field in &flow.aggregate_fields {
                collect_expression_carriers(&field.value, out);
            }
            for item in &flow.tuple_items {
                collect_expression_carriers(item, out);
            }
            for spread in &flow.spreads {
                collect_expression_carriers(spread, out);
            }
        }

        fn walk(
            events: &[FlowEvent],
            receiver_facts: &[CallReceiverFact],
            calls: &mut ahash::AHashMap<Span, CompilerCallAttribution>,
            return_spans: &mut Vec<Span>,
            writes: &mut Vec<CompilerWriteAttribution>,
        ) {
            for event in events {
                match event {
                    FlowEvent::Call {
                        span,
                        name,
                        receiver,
                        receiver_types,
                        call_kind,
                        args,
                    } => {
                        let mut receiver_source_names = ahash::AHashSet::default();
                        if let Some(fact) = call_receiver_fact_for_span(receiver_facts, *span) {
                            collect_expression_carriers(&fact.value_flow, &mut receiver_source_names);
                        }
                        let mut receiver_source_names = receiver_source_names.into_iter().collect::<Vec<_>>();
                        receiver_source_names.sort();
                        calls.insert(
                            *span,
                            CompilerCallAttribution {
                                span: *span,
                                name: name.clone(),
                                call_kind: *call_kind,
                                args: args
                                    .iter()
                                    .map(|arg| CompilerCallArgumentAttribution {
                                        span: arg.span,
                                        value_text: arg.value_text.clone(),
                                        place: arg.place.clone(),
                                        source_names: arg.source_names.clone(),
                                    })
                                    .collect(),
                                receiver: receiver.clone(),
                                receiver_source_names,
                                receiver_types: receiver_types.clone(),
                            },
                        );
                    }
                    FlowEvent::Assign {
                        span,
                        target,
                        source_name,
                        source_names,
                        source_call,
                        source_call_args,
                        ..
                    } => {
                        let mut write_sources = source_name.iter().cloned().collect::<Vec<_>>();
                        write_sources.extend(source_names.iter().cloned());
                        writes.push(CompilerWriteAttribution {
                            span: *span,
                            target: target.clone(),
                            source_names: write_sources,
                        });
                        if let Some(name) = source_call {
                            calls.entry(*span).or_insert_with(|| CompilerCallAttribution {
                                span: *span,
                                name: name.clone(),
                                call_kind: CallKind::Function,
                                args: source_call_args
                                    .iter()
                                    .map(|argument| {
                                        let argument = argument.trim();
                                        let carrier =
                                            is_bare_identifier(argument).then(|| argument.to_string());
                                        CompilerCallArgumentAttribution {
                                            span: *span,
                                            value_text: argument.to_string(),
                                            place: carrier.clone(),
                                            source_names: carrier.into_iter().collect(),
                                        }
                                    })
                                    .collect(),
                                receiver: None,
                                receiver_source_names: Vec::new(),
                                receiver_types: Vec::new(),
                            });
                        }
                    }
                    FlowEvent::Return { span, .. } => return_spans.push(*span),
                    FlowEvent::Branch {
                        then_events,
                        else_events,
                        ..
                    } => {
                        walk(then_events, receiver_facts, calls, return_spans, writes);
                        walk(else_events, receiver_facts, calls, return_spans, writes);
                    }
                    FlowEvent::Loop { body, .. }
                    | FlowEvent::Defer { body, .. }
                    | FlowEvent::Using { body, .. } => {
                        walk(body, receiver_facts, calls, return_spans, writes);
                    }
                    FlowEvent::Try {
                        body,
                        catch_events,
                        finally_events,
                        ..
                    } => {
                        walk(body, receiver_facts, calls, return_spans, writes);
                        walk(catch_events, receiver_facts, calls, return_spans, writes);
                        walk(finally_events, receiver_facts, calls, return_spans, writes);
                    }
                    _ => {}
                }
            }
        }

        let mut functions = Vec::new();
        for decl in &index.defs {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let mut calls = ahash::AHashMap::default();
            let mut return_spans = Vec::new();
            let mut writes = Vec::new();
            walk(
                &decl.flow_events,
                &index.call_receivers,
                &mut calls,
                &mut return_spans,
                &mut writes,
            );
            let mut calls = calls.into_values().collect::<Vec<_>>();
            calls.sort_by_key(|call| {
                (
                    call.span.file.raw(),
                    call.span.start,
                    std::cmp::Reverse(call.span.end),
                )
            });
            return_spans.sort_by_key(|span| (span.file.raw(), span.start, span.end));
            return_spans.dedup();
            functions.push(CompilerFunctionAttribution {
                declaration_span: decl.span,
                calls,
                return_spans,
                writes,
            });
        }
        functions.sort_by_key(|function| {
            (
                function.declaration_span.file.raw(),
                function.declaration_span.start,
                function.declaration_span.end,
            )
        });
        Self {
            file: index.file,
            functions,
        }
    }

    /// Find one exact declaration projection without decoding sibling bodies.
    #[must_use]
    pub fn function_at_span(&self, span: Span) -> Option<&CompilerFunctionAttribution> {
        let key = |value: Span| (value.file.raw(), value.start, value.end);
        let wanted = key(span);
        let index = self
            .functions
            .binary_search_by_key(&wanted, |function| key(function.declaration_span))
            .ok()?;
        self.functions.get(index)
    }
}

impl CompilerSyntaxHeader {
    /// Project the complete file-local call surface from canonical adapter IR.
    #[must_use]
    pub fn from_decl_index(index: &DeclIndex) -> Self {
        fn push_unique(values: &mut Vec<String>, value: &str) {
            let value = value.trim();
            if !value.is_empty() && !values.iter().any(|existing| existing == value) {
                values.push(value.to_string());
            }
        }

        fn walk(
            events: &[FlowEvent],
            assignment_values: &ahash::AHashMap<Span, &AssignmentValueFact>,
            calls: &mut Vec<CompilerCallHeader>,
            assignment_aliases: &mut Vec<CompilerAssignmentAlias>,
            factory_assignments: &mut Vec<CompilerFactoryCallAssignment>,
        ) {
            for event in events {
                match event {
                    FlowEvent::Call {
                        name,
                        receiver,
                        receiver_types,
                        call_kind,
                        ..
                    } => calls.push(CompilerCallHeader {
                        name: name.clone(),
                        receiver: receiver.clone(),
                        receiver_types: receiver_types.clone(),
                        call_kind: *call_kind,
                    }),
                    FlowEvent::Assign {
                        span,
                        target,
                        source_name,
                        source_call,
                        ..
                    } => {
                        let indexed = assignment_values.get(span).copied();
                        if let Some(source) = source_name.as_deref() {
                            let target = target.trim();
                            let source = source.trim();
                            if !target.is_empty() && !source.is_empty() {
                                assignment_aliases.push(CompilerAssignmentAlias {
                                    target: target.to_string(),
                                    source: source.to_string(),
                                });
                            }
                        }
                        if let Some(name) = source_call
                            .as_deref()
                            .map(str::trim)
                            .filter(|name| !name.is_empty())
                        {
                            calls.push(CompilerCallHeader {
                                name: name.to_string(),
                                receiver: indexed
                                    .and_then(|fact| fact.direct_call_receiver.as_deref())
                                    .map(str::to_string),
                                receiver_types: Vec::new(),
                                call_kind: CallKind::Function,
                            });
                        }
                        let call_name = indexed
                            .and_then(|fact| fact.direct_call_name.as_deref())
                            .or(source_call.as_deref())
                            .map(str::trim)
                            .filter(|name| !name.is_empty());
                        if let Some(call_name) = call_name {
                            let target = target.trim();
                            if !target.is_empty() {
                                factory_assignments.push(CompilerFactoryCallAssignment {
                                    target: target.to_string(),
                                    call_name: call_name.to_string(),
                                    call_receiver: indexed
                                        .and_then(|fact| fact.direct_call_receiver.as_deref())
                                        .map(str::to_string),
                                });
                            }
                        }
                    }
                    FlowEvent::Branch {
                        then_events,
                        else_events,
                        ..
                    } => {
                        walk(
                            then_events,
                            assignment_values,
                            calls,
                            assignment_aliases,
                            factory_assignments,
                        );
                        walk(
                            else_events,
                            assignment_values,
                            calls,
                            assignment_aliases,
                            factory_assignments,
                        );
                    }
                    FlowEvent::Loop { body, .. }
                    | FlowEvent::Defer { body, .. }
                    | FlowEvent::Using { body, .. } => {
                        walk(
                            body,
                            assignment_values,
                            calls,
                            assignment_aliases,
                            factory_assignments,
                        );
                    }
                    FlowEvent::Try {
                        body,
                        catch_events,
                        finally_events,
                        ..
                    } => {
                        walk(
                            body,
                            assignment_values,
                            calls,
                            assignment_aliases,
                            factory_assignments,
                        );
                        walk(
                            catch_events,
                            assignment_values,
                            calls,
                            assignment_aliases,
                            factory_assignments,
                        );
                        walk(
                            finally_events,
                            assignment_values,
                            calls,
                            assignment_aliases,
                            factory_assignments,
                        );
                    }
                    _ => {}
                }
            }
        }

        let mut out = Self::default();
        let assignment_values = index
            .assignment_values
            .iter()
            .map(|fact| (fact.assignment_span, fact))
            .collect::<ahash::AHashMap<_, _>>();
        for decl in &index.defs {
            walk(
                &decl.flow_events,
                &assignment_values,
                &mut out.calls,
                &mut out.assignment_aliases,
                &mut out.factory_assignments,
            );
            for alias in &decl.type_aliases {
                if !alias.name.trim().is_empty()
                    && !alias.type_name.trim().is_empty()
                    && !out.type_aliases.iter().any(|existing| existing == alias)
                {
                    out.type_aliases.push(alias.clone());
                }
            }
        }
        for reference in &index.refs {
            if reference.kind == RefKind::Call && !reference.name.trim().is_empty() {
                out.calls.push(CompilerCallHeader {
                    name: reference.name.clone(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                });
            }
        }
        for call in &mut out.calls {
            call.receiver_types.sort();
            call.receiver_types.dedup();
        }
        out.calls.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.call_kind.as_str().cmp(right.call_kind.as_str()))
                .then_with(|| left.receiver.cmp(&right.receiver))
                .then_with(|| left.receiver_types.cmp(&right.receiver_types))
        });
        out.calls.dedup_by(|left, right| left == right);
        out.assignment_aliases.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then_with(|| left.source.cmp(&right.source))
        });
        out.assignment_aliases.dedup_by(|left, right| left == right);
        out.factory_assignments.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then_with(|| left.call_name.cmp(&right.call_name))
                .then_with(|| left.call_receiver.cmp(&right.call_receiver))
        });
        out.factory_assignments.dedup();
        out.type_aliases.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.type_name.cmp(&right.type_name))
        });
        out.type_aliases.dedup();

        // Retain stable first-seen receiver type spellings while avoiding a
        // separate set allocation in every small compiler object.
        for call in &mut out.calls {
            let mut normalized = Vec::with_capacity(call.receiver_types.len());
            for receiver_type in &call.receiver_types {
                push_unique(&mut normalized, receiver_type);
            }
            call.receiver_types = normalized;
        }
        out
    }
}

impl FlowEvent {
    /// Source span carried by this event.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            FlowEvent::Call { span, .. }
            | FlowEvent::Branch { span, .. }
            | FlowEvent::Loop { span, .. }
            | FlowEvent::Assign { span, .. }
            | FlowEvent::AggregateAssign { span, .. }
            | FlowEvent::Return { span, .. }
            | FlowEvent::Throw { span, .. }
            | FlowEvent::Try { span, .. }
            | FlowEvent::Break { span, .. }
            | FlowEvent::Continue { span, .. }
            | FlowEvent::Yield { span, .. }
            | FlowEvent::Await { span, .. }
            | FlowEvent::Defer { span, .. }
            | FlowEvent::Using { span, .. }
            | FlowEvent::Lifecycle { span, .. } => *span,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Function,
    Method,
    Constructor,
    Macro,
    /// Syntax-level operator application lowered from an AST operator node.
    /// Its result is data-dependent on its operands and it never resolves as
    /// a workspace callable merely because the operator has a text spelling.
    Operator,
    Indirect,
    /// Language-level channel send lowered from a dedicated AST node.
    ChannelSend,
    /// Assignment through a parser-proven index/subscript place. The
    /// operation carries the index and assigned value as arguments without
    /// pretending that source syntax invoked a provider/runtime method.
    IndexWrite,
}

impl CallKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CallKind::Function => "function",
            CallKind::Method => "method",
            CallKind::Constructor => "constructor",
            CallKind::Macro => "macro",
            CallKind::Operator => "operator",
            CallKind::Indirect => "indirect",
            CallKind::ChannelSend => "channel_send",
            CallKind::IndexWrite => "index_write",
        }
    }
}

/// Shape classification of an assignment's RHS for Phase-5
/// const-propagation. The adapter sets this when the CST shape
/// is unambiguous; the engine uses it to skip name-bridging when
/// the RHS can't carry taint (`Literal`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignValueKind {
    /// Pure literal — number, string, boolean, char, null,
    /// constant enum, array/list of literals. The RHS cannot
    /// carry taint, so the engine can treat the write as a clean
    /// overwrite that kills prior writers.
    Literal,
    /// RHS is a call expression. Whether it carries taint
    /// depends on the callee's return-value summary; the engine
    /// routes through CallRet → Write.
    CallResult,
    /// RHS is delivered to a call-site block / closure by the
    /// callee's `yield`, not by the callee's ordinary return value.
    /// Engines should require a resolved yield summary rather than
    /// treating tainted call arguments as enough evidence.
    YieldResult,
    /// A binding projected from an aggregate pattern. The bound value is
    /// reachable from both the aggregate and the exact selected field, so
    /// engines preserve both edges instead of treating the aggregate token
    /// as imprecise field metadata.
    Destructure,
    /// RHS is a syntax-proven callable reference rather than a call. The
    /// canonical referenced symbol is carried in `source_name`; resolvers may
    /// bind the assignment target as an indirect callable without inventing a
    /// return-value edge.
    CallableReference,
    /// RHS is a compound expression (member access, binary op,
    /// template literal, ternary, conditional, …). Adapters provide its
    /// AST-derived carriers through structured expression-flow facts.
    Compound,
    /// RHS shape couldn't be classified (or the adapter doesn't
    /// surface enough info). Engine treats as `Compound` for
    /// safety.
    Unknown,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopKind {
    For,
    While,
    DoWhile,
    ForEach,
    Loop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallArg {
    pub span: Span,
    /// AST-derived argument passing semantics. `WriteBack` means the
    /// callee may update the addressable [`Self::place`] and the caller must
    /// observe that update after the call.
    #[serde(default)]
    pub passing_mode: ArgumentPassingMode,
    /// Keyword-argument name (Python / Ruby / C# named args). `None` for positional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The argument's text verbatim. Retained for rendering and exact
    /// callable/literal resolver spelling; dataflow consumers must not parse
    /// this string for value carriers. Those come exclusively from the
    /// parser-derived [`Self::place`] and [`Self::source_names`] facts.
    pub value_text: String,
    /// Adapter-normalized place key when the argument expression is an
    /// addressable/mutable location according to the parsed grammar
    /// (identifier, member access, subscript, pointer/address expression).
    /// Opaque-call side-effect modeling consumes this instead of guessing
    /// from raw argument text or API names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// Adapter-extracted value operands inside this argument expression.
    /// This is the call-argument counterpart to `FlowEvent::Assign::source_names`:
    /// a template/interpolated argument such as `` `${cmd}` `` or `f"{cmd}"`
    /// should carry `["cmd"]` here because the parser surfaced a real
    /// expression node. The taint engine must not parse language-specific
    /// interpolation syntax out of `value_text`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentPassingMode {
    #[default]
    Value,
    WriteBack,
}

/// A language-neutral syntactic operation derived from [`FlowEvent`].
///
/// Operations are use-site facts: they make reads, writes, calls,
/// returns, throws, awaits, resource scopes, and lifecycle transitions
/// visible without each consumer re-walking the flow-event tree. They
/// are still syntax facts: this layer does not invent edges, resolve
/// call targets, or parse raw file text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub span: Span,
    pub kind: OperationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operands: Vec<OperationOperand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Shared operation vocabulary used by browse, SDK, security, and future
/// abstract-interpretation consumers.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Read,
    Write,
    Call,
    Index,
    Deref,
    FieldAccess,
    Cast,
    ResourceUse,
    Allocate,
    Release,
    Lifecycle,
    Return,
    Throw,
    Await,
    Yield,
    BranchCondition,
    CatchBinding,
    ExternalBoundary,
}

impl OperationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationKind::Read => "read",
            OperationKind::Write => "write",
            OperationKind::Call => "call",
            OperationKind::Index => "index",
            OperationKind::Deref => "deref",
            OperationKind::FieldAccess => "field_access",
            OperationKind::Cast => "cast",
            OperationKind::ResourceUse => "resource_use",
            OperationKind::Allocate => "allocate",
            OperationKind::Release => "release",
            OperationKind::Lifecycle => "lifecycle",
            OperationKind::Return => "return",
            OperationKind::Throw => "throw",
            OperationKind::Await => "await",
            OperationKind::Yield => "yield",
            OperationKind::BranchCondition => "branch_condition",
            OperationKind::CatchBinding => "catch_binding",
            OperationKind::ExternalBoundary => "external_boundary",
        }
    }
}

/// Named input/output of an [`Operation`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationOperand {
    pub name: String,
    pub role: OperationOperandRole,
}

/// Role a named operand plays within an operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOperandRole {
    Read,
    Write,
    Receiver,
    Argument,
    Callee,
    Condition,
    Returned,
    Thrown,
    Resource,
    Transition,
}

impl OperationOperandRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationOperandRole::Read => "read",
            OperationOperandRole::Write => "write",
            OperationOperandRole::Receiver => "receiver",
            OperationOperandRole::Argument => "argument",
            OperationOperandRole::Callee => "callee",
            OperationOperandRole::Condition => "condition",
            OperationOperandRole::Returned => "returned",
            OperationOperandRole::Thrown => "thrown",
            OperationOperandRole::Resource => "resource",
            OperationOperandRole::Transition => "transition",
        }
    }
}

/// Convert a flow-event tree into first-class operation facts.
///
/// The conversion is deliberately conservative. It only uses the
/// normalized fields already carried by [`FlowEvent`] and [`CallArg`];
/// when an adapter has not surfaced an operand, this function leaves it
/// absent instead of deriving it from raw source text.
#[must_use]
pub fn operations_from_flow_events(events: &[FlowEvent]) -> Vec<Operation> {
    let mut out = Vec::new();
    collect_operations(events, &mut out);
    for op in &mut out {
        dedup_operands(&mut op.operands);
    }
    out
}

fn collect_operations(events: &[FlowEvent], out: &mut Vec<Operation>) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                call_kind,
                args,
                ..
            } => {
                let mut operands = vec![OperationOperand {
                    name: name.clone(),
                    role: OperationOperandRole::Callee,
                }];
                if let Some(receiver) = non_empty(receiver.as_deref()) {
                    operands.push(OperationOperand {
                        name: receiver.to_string(),
                        role: OperationOperandRole::Receiver,
                    });
                }
                for arg in args {
                    push_call_arg_operands(&mut operands, arg);
                }
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Call,
                    target: Some(name.clone()),
                    operands,
                    detail: Some(call_kind.as_str().to_string()),
                });
                if matches!(call_kind, CallKind::Constructor) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Allocate,
                        target: Some(name.clone()),
                        operands: vec![OperationOperand {
                            name: name.clone(),
                            role: OperationOperandRole::Callee,
                        }],
                        detail: Some("constructor".to_string()),
                    });
                }
                if let Some(receiver) = non_empty(receiver.as_deref()) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(receiver.to_string()),
                        operands: vec![OperationOperand {
                            name: receiver.to_string(),
                            role: OperationOperandRole::Receiver,
                        }],
                        detail: Some("call_receiver".to_string()),
                    });
                    push_place_shape_operations(*span, receiver, OperationOperandRole::Receiver, out);
                }
                for arg in args {
                    push_call_arg_read_operations(*span, arg, out);
                }
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if let Some(condition) = non_empty(condition.as_deref()) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::BranchCondition,
                        target: Some(condition.to_string()),
                        operands: vec![OperationOperand {
                            name: condition.to_string(),
                            role: OperationOperandRole::Condition,
                        }],
                        detail: None,
                    });
                }
                collect_operations(then_events, out);
                collect_operations(else_events, out);
            }
            FlowEvent::Loop { body, .. } => collect_operations(body, out),
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                let mut operands = vec![OperationOperand {
                    name: target.clone(),
                    role: OperationOperandRole::Write,
                }];
                push_optional_operand(&mut operands, source_name.as_deref(), OperationOperandRole::Read);
                push_optional_operand(
                    &mut operands,
                    source_call.as_deref(),
                    OperationOperandRole::Callee,
                );
                for source in source_names {
                    push_optional_operand(&mut operands, Some(source.as_str()), OperationOperandRole::Read);
                }
                for arg in source_call_args {
                    push_optional_operand(&mut operands, Some(arg.as_str()), OperationOperandRole::Argument);
                }
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Write,
                    target: Some(target.clone()),
                    operands,
                    detail: None,
                });
                push_place_shape_operations(*span, target, OperationOperandRole::Write, out);
                if let Some(source) = non_empty(source_name.as_deref()) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(source.to_string()),
                        operands: vec![OperationOperand {
                            name: source.to_string(),
                            role: OperationOperandRole::Read,
                        }],
                        detail: Some("assign_source".to_string()),
                    });
                    push_place_shape_operations(*span, source, OperationOperandRole::Read, out);
                }
                for source in source_names {
                    if let Some(source) = non_empty(Some(source.as_str())) {
                        out.push(Operation {
                            span: *span,
                            kind: OperationKind::Read,
                            target: Some(source.to_string()),
                            operands: vec![OperationOperand {
                                name: source.to_string(),
                                role: OperationOperandRole::Read,
                            }],
                            detail: Some("assign_source".to_string()),
                        });
                        push_place_shape_operations(*span, source, OperationOperandRole::Read, out);
                    }
                }
                if let Some(call) = non_empty(source_call.as_deref()) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Call,
                        target: Some(call.to_string()),
                        operands: source_call_args
                            .iter()
                            .filter_map(|arg| non_empty(Some(arg.as_str())))
                            .map(|arg| OperationOperand {
                                name: arg.to_string(),
                                role: OperationOperandRole::Argument,
                            })
                            .collect(),
                        detail: Some("assignment_source".to_string()),
                    });
                }
            }
            FlowEvent::AggregateAssign {
                span,
                target,
                value_flow,
                ..
            } => {
                let sources = expression_flow_source_names(value_flow);
                let mut operands = vec![OperationOperand {
                    name: target.clone(),
                    role: OperationOperandRole::Write,
                }];
                operands.extend(sources.iter().cloned().map(|name| OperationOperand {
                    name,
                    role: OperationOperandRole::Read,
                }));
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Write,
                    target: Some(target.clone()),
                    operands,
                    detail: Some("aggregate_initializer".to_string()),
                });
                push_place_shape_operations(*span, target, OperationOperandRole::Write, out);
                for source in sources {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(source.clone()),
                        operands: vec![OperationOperand {
                            name: source.clone(),
                            role: OperationOperandRole::Read,
                        }],
                        detail: Some("aggregate_initializer".to_string()),
                    });
                    push_place_shape_operations(*span, &source, OperationOperandRole::Read, out);
                }
            }
            FlowEvent::Return {
                span,
                value_text,
                value_name,
                value_flow,
            } => {
                let target = value_name
                    .as_ref()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| value_text.as_ref().filter(|s| !s.trim().is_empty()))
                    .cloned();
                let sources = expression_flow_source_names(value_flow);
                let operands = sources
                    .iter()
                    .map(|source| OperationOperand {
                        name: source.clone(),
                        role: OperationOperandRole::Returned,
                    })
                    .collect();
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Return,
                    target,
                    operands,
                    detail: None,
                });
                for value in sources {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(value.clone()),
                        operands: vec![OperationOperand {
                            name: value.clone(),
                            role: OperationOperandRole::Returned,
                        }],
                        detail: Some("return_value".to_string()),
                    });
                    push_place_shape_operations(*span, &value, OperationOperandRole::Returned, out);
                }
            }
            FlowEvent::Throw {
                span,
                value_name,
                thrown_type,
            } => {
                let mut operands = Vec::new();
                push_optional_operand(&mut operands, value_name.as_deref(), OperationOperandRole::Thrown);
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Throw,
                    target: value_name.clone().or_else(|| thrown_type.clone()),
                    operands,
                    detail: thrown_type.clone(),
                });
                if let Some(value) = non_empty(value_name.as_deref()) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(value.to_string()),
                        operands: vec![OperationOperand {
                            name: value.to_string(),
                            role: OperationOperandRole::Thrown,
                        }],
                        detail: Some("throw_value".to_string()),
                    });
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                collect_operations(body, out);
                if let Some(catch_param) = non_empty(catch_param.as_deref()) {
                    out.push(Operation {
                        span: event.span(),
                        kind: OperationKind::CatchBinding,
                        target: Some(catch_param.to_string()),
                        operands: vec![OperationOperand {
                            name: catch_param.to_string(),
                            role: OperationOperandRole::Write,
                        }],
                        detail: None,
                    });
                }
                collect_operations(catch_events, out);
                collect_operations(finally_events, out);
            }
            FlowEvent::Yield {
                span,
                value_text,
                value_flow,
            } => {
                let sources = expression_flow_source_names(value_flow);
                let source_syntax = value_text
                    .as_deref()
                    .map(str::trim)
                    .filter(|text| !text.is_empty() && value_flow.place.is_some() && sources.len() == 1);
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Yield,
                    target: value_text.clone().filter(|s| !s.trim().is_empty()),
                    operands: sources
                        .iter()
                        .map(|source| OperationOperand {
                            name: source.clone(),
                            role: OperationOperandRole::Returned,
                        })
                        .collect(),
                    detail: None,
                });
                for value in sources {
                    let rendered = source_syntax.unwrap_or(&value);
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(rendered.to_string()),
                        operands: vec![OperationOperand {
                            name: rendered.to_string(),
                            role: OperationOperandRole::Returned,
                        }],
                        detail: Some("yield_value".to_string()),
                    });
                    push_place_shape_operations(*span, rendered, OperationOperandRole::Returned, out);
                }
            }
            FlowEvent::Await { span, value_name } => {
                let mut operands = Vec::new();
                push_optional_operand(&mut operands, value_name.as_deref(), OperationOperandRole::Read);
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::Await,
                    target: value_name.clone(),
                    operands,
                    detail: None,
                });
                if let Some(value) = non_empty(value_name.as_deref()) {
                    out.push(Operation {
                        span: *span,
                        kind: OperationKind::Read,
                        target: Some(value.to_string()),
                        operands: vec![OperationOperand {
                            name: value.to_string(),
                            role: OperationOperandRole::Read,
                        }],
                        detail: Some("await_value".to_string()),
                    });
                }
            }
            FlowEvent::Defer { body, .. } => collect_operations(body, out),
            FlowEvent::Using { span, body } => {
                out.push(Operation {
                    span: *span,
                    kind: OperationKind::ResourceUse,
                    target: None,
                    operands: Vec::new(),
                    detail: Some("using_scope".to_string()),
                });
                collect_operations(body, out);
            }
            FlowEvent::Lifecycle {
                span,
                name,
                transition,
            } => {
                let kind = if is_release_transition(transition) {
                    OperationKind::Release
                } else {
                    OperationKind::Lifecycle
                };
                out.push(Operation {
                    span: *span,
                    kind,
                    target: Some(name.clone()),
                    operands: vec![
                        OperationOperand {
                            name: name.clone(),
                            role: OperationOperandRole::Resource,
                        },
                        OperationOperand {
                            name: transition.clone(),
                            role: OperationOperandRole::Transition,
                        },
                    ],
                    detail: Some(transition.clone()),
                });
            }
            FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {}
        }
    }
}

fn push_call_arg_operands(out: &mut Vec<OperationOperand>, arg: &CallArg) {
    if let Some(place) = non_empty(arg.place.as_deref()) {
        out.push(OperationOperand {
            name: place.to_string(),
            role: OperationOperandRole::Argument,
        });
    }
    for source in &arg.source_names {
        push_optional_operand(out, Some(source.as_str()), OperationOperandRole::Read);
    }
}

fn push_call_arg_read_operations(span: Span, arg: &CallArg, out: &mut Vec<Operation>) {
    if let Some(place) = non_empty(arg.place.as_deref()) {
        out.push(Operation {
            span,
            kind: OperationKind::Read,
            target: Some(place.to_string()),
            operands: vec![OperationOperand {
                name: place.to_string(),
                role: OperationOperandRole::Argument,
            }],
            detail: Some("call_argument".to_string()),
        });
        push_place_shape_operations(span, place, OperationOperandRole::Argument, out);
    }
    for source in &arg.source_names {
        if let Some(source) = non_empty(Some(source.as_str())) {
            out.push(Operation {
                span,
                kind: OperationKind::Read,
                target: Some(source.to_string()),
                operands: vec![OperationOperand {
                    name: source.to_string(),
                    role: OperationOperandRole::Argument,
                }],
                detail: Some("call_argument".to_string()),
            });
            push_place_shape_operations(span, source, OperationOperandRole::Argument, out);
        }
    }
}

fn push_place_shape_operations(
    span: Span,
    place: &str,
    role: OperationOperandRole,
    out: &mut Vec<Operation>,
) {
    if place_has_index_shape(place) {
        out.push(Operation {
            span,
            kind: OperationKind::Index,
            target: Some(place.to_string()),
            operands: vec![OperationOperand {
                name: place.to_string(),
                role,
            }],
            detail: Some("normalized_place".to_string()),
        });
    }
    if place_has_deref_shape(place) {
        out.push(Operation {
            span,
            kind: OperationKind::Deref,
            target: Some(place.to_string()),
            operands: vec![OperationOperand {
                name: place.to_string(),
                role,
            }],
            detail: Some("normalized_place".to_string()),
        });
    }
    if place_has_field_shape(place) {
        out.push(Operation {
            span,
            kind: OperationKind::FieldAccess,
            target: Some(place.to_string()),
            operands: vec![OperationOperand {
                name: place.to_string(),
                role,
            }],
            detail: Some("normalized_place".to_string()),
        });
    }
}

fn place_has_index_shape(place: &str) -> bool {
    place.contains('[') && place.contains(']')
}

fn place_has_deref_shape(place: &str) -> bool {
    let trimmed = place.trim_start();
    trimmed.starts_with('*') || trimmed.starts_with('&')
}

fn place_has_field_shape(place: &str) -> bool {
    bonsai_common::qualified_name_owner(place).is_some()
}

fn push_optional_operand(out: &mut Vec<OperationOperand>, name: Option<&str>, role: OperationOperandRole) {
    if let Some(name) = non_empty(name) {
        out.push(OperationOperand {
            name: name.to_string(),
            role,
        });
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(|s| {
        let trimmed = s.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

fn expression_flow_source_names(flow: &ExpressionFlow) -> Vec<String> {
    fn collect(flow: &ExpressionFlow, out: &mut Vec<String>) {
        if let Some(place) = non_empty(flow.place.as_deref()) {
            out.push(place.to_string());
        }
        out.extend(
            flow.source_names
                .iter()
                .filter(|name| !name.trim().is_empty())
                .cloned(),
        );
        for field in &flow.aggregate_fields {
            collect(&field.value, out);
        }
        for item in &flow.tuple_items {
            collect(item, out);
        }
        for spread in &flow.spreads {
            collect(spread, out);
        }
    }
    let mut out = Vec::new();
    collect(flow, &mut out);
    out.sort();
    out.dedup();
    out
}

fn is_release_transition(transition: &str) -> bool {
    matches!(
        transition,
        "freed" | "closed" | "unlocked" | "cancelled" | "canceled" | "moved"
    )
}

fn dedup_operands(operands: &mut Vec<OperationOperand>) {
    let mut seen = std::collections::HashSet::new();
    operands.retain(|operand| seen.insert((operand.role, operand.name.clone())));
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefKind {
    Read,
    Write,
    Call,
    Type,
    Macro,
    Import,
    Decorator,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ref {
    pub span: Span,
    pub name: String,
    pub kind: RefKind,
    /// Owning scope in which the reference appears, if known.
    pub scope: Option<SymbolId>,
    /// Best-effort resolution done at extraction time; resolver may refine it.
    pub resolved: Option<SymbolId>,
}

/// Exact Tree-sitter relationship between an assignment-shaped syntax node,
/// its target/pattern, and its RHS expression. Consumers may render these
/// spans from the file snapshot, but must not split the surrounding assignment
/// text to recover expression structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentValueFact {
    pub assignment_span: Span,
    /// Adapter-normalized target place when the parsed assignment binds one
    /// addressable value. Multi-target patterns deliberately leave this
    /// unset; their individual flow bindings remain in [`FlowEvent::Assign`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The owning language frontend proved that this assignment initializes
    /// an immutable binding/field. Consumers may use this to carry exact
    /// constructor state across declarations without guessing modifiers.
    #[serde(default)]
    pub target_is_immutable: bool,
    /// Declaration that owns an immutable target when the frontend can bind
    /// it exactly (for example the containing class of a final field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_owner: Option<SymbolId>,
    /// Exact parsed target/pattern node, when the grammar exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_span: Option<Span>,
    pub value_span: Span,
    /// Exact call-expression nodes whose results participate in the RHS
    /// value. These are extracted from the RHS tree, never recovered from
    /// assignment text. Callable-reference syntax deliberately leaves this
    /// empty because it denotes a function value rather than an invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_sites: Vec<Span>,
    /// Compiler-owned value dependencies for the exact RHS node.
    /// Rendered source remains available through [`AssignmentValueIndex`],
    /// but semantic consumers must use this structure instead of tokenizing
    /// that rendering.
    #[serde(default, skip_serializing_if = "ExpressionFlow::is_empty")]
    pub value_flow: ExpressionFlow,
    /// Exact return value of a callable assigned by this syntax node when the
    /// language frontend proves that the callable body consists of one
    /// unconditional return. Absent for multi-path, fallthrough, or otherwise
    /// non-exact callable bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_callable_return: Option<ExpressionFlow>,
    /// Exact scalar arguments of the direct RHS call when every argument was
    /// decoded by the owning language frontend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_static_call_args: Option<Vec<StaticScalarValue>>,
    /// Canonical callee when the RHS is (or transparently wraps) one direct
    /// call. This comes from the Tree-sitter call node selected by the
    /// adapter, never from scanning the rendered RHS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_call_name: Option<String>,
    /// Canonical receiver for [`Self::direct_call_name`], when the parsed call
    /// is receiver-qualified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_call_receiver: Option<String>,
}

/// One exact key/value entry in a statically initialized string map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticStringMapEntry {
    pub key: String,
    pub value: String,
}

/// A complete, spread-free string map lowered by a language frontend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticStringMapFact {
    pub assignment_span: Span,
    pub target: String,
    pub entries: Vec<StaticStringMapEntry>,
}

/// One exact value in a compiler-lowered string composition.
///
/// Language frontends emit these parts only when their grammar proves the
/// complete expression shape. Shared analyses can consequently reason about
/// reconstructed values without reparsing display text or carrying
/// language-specific operator spellings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StringCompositionPart {
    Literal {
        value: String,
    },
    Place {
        place: String,
    },
    /// A value selected by the language's null/falsey fallback operator,
    /// such as Python's `value or "/"`.
    PlaceOrLiteral {
        place: String,
        fallback: String,
    },
    /// Result of one exact call expression in the composition. The rulepack
    /// assigns security meaning to the callee/receiver; the adapter records
    /// only the parsed value relationship.
    Call {
        span: Span,
    },
    /// Exact call result with a language-level null/falsey fallback.
    CallOrLiteral {
        span: Span,
        fallback: String,
    },
}

/// A complete string composition lowered from one parsed expression.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringCompositionFact {
    /// The assignment/return syntax node that owns the composed value.
    pub container_span: Span,
    /// The exact parsed value-expression node.
    pub value_span: Span,
    /// Assignment target when the composition is bound before use. Return
    /// compositions leave this unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub parts: Vec<StringCompositionPart>,
}

/// A value selected exclusively from a finite, compiler-proven literal map.
///
/// The dynamic key controls *which* literal is chosen but never becomes part
/// of the selected value. Language frontends prove their own map declaration
/// and lookup syntax; shared flow/security code consumes only this semantic
/// fact. A selection is attached either to its owning assignment or to the
/// exact call argument that consumes it directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiniteLiteralSelectionFact {
    pub selection_span: Span,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_span: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_span: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument_index: Option<usize>,
}

/// Domain on which a character-substitution helper applies its static map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CharacterSubstitutionDomain {
    /// Every input character is looked up and missing entries preserve the
    /// original character.
    TableKeysWithIdentityFallback,
    /// Only these exact compiler-decoded characters enter the replacement
    /// callback (for example an exact regular-expression character class).
    ExactCharacters { characters: Vec<String> },
}

/// A local function whose return value is a character-wise static-map
/// substitution of one input parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharacterSubstitutionFact {
    pub function_span: Span,
    pub transform_span: Span,
    pub input_param_index: usize,
    /// Exact substitutions decoded directly from the transform expression.
    /// This is used for chained language-native replacements where no
    /// separately named lookup table exists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_mappings: Vec<StaticStringMapEntry>,
    /// Optional name of a complete static lookup table. Older adapter shapes
    /// use this instead of `exact_mappings`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub table: String,
    pub domain: CharacterSubstitutionDomain,
}

/// Language-runtime character classes whose output alphabet is exact.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CharacterClass {
    Alphabetic,
    Alphanumeric,
    Digit,
}

/// Compiler-proven alphabet constraint produced by a local transform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CharacterConstraintDomain {
    /// Output consists only of characters accepted by these runtime classes
    /// or the listed exact scalar characters.
    AllowOnly {
        classes: Vec<CharacterClass>,
        exact_characters: Vec<String>,
    },
    /// Every listed character is absent from the output.
    ExcludesExact { characters: Vec<String> },
    /// Every listed input character is replaced by the exact decoded output.
    /// This describes configured character transformers without assigning
    /// security meaning to either the provider or the mapping.
    SubstitutesExact { mappings: Vec<StaticStringMapEntry> },
    /// A syntactically proven candidate whose runtime meaning depends on a
    /// rulepack-selected factory/operation pair. Adapters record exact call
    /// identity and the derived domain; they do not classify the provider as
    /// a sanitizer themselves.
    ProviderBound {
        factory_call: String,
        operation_call: String,
        domain: Box<CharacterConstraintDomain>,
    },
}

/// Where a character-constrained value is produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CharacterConstraintOutput {
    Assignment {
        target: String,
    },
    Return,
    /// One exact transform expression used directly as a call argument.
    Expression {
        span: Span,
    },
}

/// A complete Tree-sitter/runtime proof that one value has a constrained
/// output alphabet. Provider-bound facts retain exact call identity without
/// assigning security meaning; rule semantics select accepted providers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharacterConstraintFact {
    pub function_span: Span,
    pub transform_span: Span,
    /// Stable input place when the transform consumes an addressable value.
    /// Direct call results have no place; their exact call is related through
    /// `transform_span` and this field is empty.
    pub input_place: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_param_index: Option<usize>,
    pub output: CharacterConstraintOutput,
    pub domain: CharacterConstraintDomain,
}

/// Convert exact character substitutions into compiler constraints when the
/// replacement removes the original character. Adapters remain responsible
/// for proving the substitution syntax; this function only lowers typed IR.
#[must_use]
pub fn character_constraints_from_substitutions(
    defs: &[Decl],
    substitutions: &[CharacterSubstitutionFact],
) -> Vec<CharacterConstraintFact> {
    substitutions
        .iter()
        .filter_map(|fact| {
            let decl = defs.iter().find(|decl| decl.span == fact.function_span)?;
            let input_place = decl.params.get(fact.input_param_index)?.clone();
            let mut characters = fact
                .exact_mappings
                .iter()
                .filter(|mapping| !mapping.value.contains(&mapping.key))
                .map(|mapping| mapping.key.clone())
                .collect::<Vec<_>>();
            characters.sort();
            characters.dedup();
            (!characters.is_empty()).then_some(CharacterConstraintFact {
                function_span: fact.function_span,
                transform_span: fact.transform_span,
                input_place,
                input_param_index: Some(fact.input_param_index),
                output: CharacterConstraintOutput::Return,
                domain: CharacterConstraintDomain::ExcludesExact { characters },
            })
        })
        .collect()
}

/// Compiler proof that a predicate guards every dynamic element copied from
/// one value into a clean output value.
///
/// This fact deliberately assigns no security meaning to the predicate. The
/// owning language adapter proves the control/data relationship from its CST;
/// a rule match at `predicate_call_span` decides whether that predicate is a
/// sanitizer for a particular sink category. The invariant is strict: the
/// output starts clean and every non-literal write in the owning function is
/// one of the predicate-guarded copies represented by this fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardedValueFilterFact {
    pub function_span: Span,
    pub predicate_call_span: Span,
    pub write_span: Span,
    pub input_place: String,
    pub output_place: String,
}

/// Compiler/runtime proof that a helper returns only a same-origin absolute
/// path or a static fallback. The owning adapter proves each language's URL
/// and string predicate syntax; shared analysis consumes this summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SameOriginPathConstraintFact {
    pub function_span: Span,
    pub guard_span: Span,
    /// Exact value constrained by the guard in the owning function.
    pub input_place: String,
    /// Parameter position when this fact summarizes a reusable helper.
    /// Caller-local guarded assignments intentionally leave this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_param_index: Option<usize>,
    /// Exact imported parser/provider call when the proof depends on runtime
    /// library semantics. Syntax-only proofs leave this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_call: Option<String>,
    pub rejects_scheme: bool,
    pub rejects_authority: bool,
    pub requires_absolute_path: bool,
    pub rejects_scheme_relative_path: bool,
}

/// One complete language/runtime guard proven by an adapter from its parsed
/// syntax. The capability is semantic (for example an algorithm-pinned
/// callback), never an API spelling. Rule-selected consumers may attach the
/// proof only to the exact guarded call in the owning function.
pub const COMPILER_GUARD_RELATIVE_PATH_BOUNDARY_REJECTION: &str = "path.relative-boundary-rejection";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerGuardFact {
    pub function_span: Span,
    pub guarded_call_span: Span,
    pub proof_span: Span,
    pub capability: String,
    /// Exact syntax roles carried by the proof (for example the callback
    /// argument position and selector chain constrained by a branch).
    /// Adapters record them without assigning security meaning; rules select
    /// the evidence required by a particular sink.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// Exact summary of a local helper that drops a finite set of dynamic keys
/// before reconstructing an object. The adapter proves loop/control/write
/// ordering and whether nested values pass through the same helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicKeyFilterFact {
    pub function_span: Span,
    pub guard_span: Span,
    pub input_param_index: usize,
    /// Exact filtered value produced by the helper. Recursive object filters
    /// name their reconstructed object; property-path filters name the
    /// segment array proven safe by the dominating guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_place: Option<String>,
    /// Constructor that owns the exact static denylist. The adapter records
    /// syntax identity only; the rulepack decides whether that constructor is
    /// meaningful for a particular sink.
    pub collection_constructor: String,
    /// Membership predicate that rejects each denylisted key.
    pub membership_check: String,
    pub rejected_exact_values: Vec<String>,
    pub recursive: bool,
}

/// One branch-local runtime type refinement proven by parsed guard syntax.
///
/// The frontend records both the full branch and the exact arm in which the
/// refinement holds. Matchers consume this fact directly; they must not
/// rediscover `instanceof` / `isinstance` / `is` structure from rendered
/// condition text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTypeNarrowingFact {
    pub branch_span: Span,
    pub guarded_span: Span,
    pub subject: String,
    pub type_name: String,
}

/// Syntactic polarity of a parsed branch condition.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchConditionPolarity {
    Positive,
    Negated,
}

/// Compiler-owned operands for a membership test in a branch condition.
///
/// `then_contains` describes the semantic condition under which the parsed
/// `then` arm executes. For example, `item in allowed` records `true`, while
/// both `item not in allowed` and `not item in allowed` record `false`.
/// Consumers therefore never need to recover `in`/`not in` tokens from
/// rendered condition text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipConditionFact {
    pub subject: String,
    pub collection: String,
    pub then_contains: bool,
}

/// Equality relation lowered from a language adapter's Tree-sitter grammar.
///
/// The shared analyzer needs only semantic equality here. Operator spellings
/// (`==`, `!=`, and language-specific equivalents) remain adapter syntax and
/// never leak into downstream policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionEquality {
    Equal,
    NotEqual,
}

/// One operand in a compiler-lowered branch expression.
///
/// Static values are populated only when the language adapter can decode the
/// complete literal without approximation. Dynamic/interpolated/escaped
/// forms remain `None`, preserving soundness for exact guard proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionOperandFact {
    pub span: Span,
    #[serde(default, skip_serializing_if = "ExpressionFlow::is_empty")]
    pub value_flow: ExpressionFlow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_string: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_value: Option<StaticScalarValue>,
}

/// Typed boolean expression for one parsed branch condition.
///
/// Language adapters own the mapping from their grammar's operator nodes to
/// these semantic forms. Shared analyses can consequently prove conjunction,
/// disjunction, negation, and equality without tokenizing rendered condition
/// text or carrying a cross-language operator inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConditionExpressionFact {
    Atom {
        span: Span,
    },
    /// Runtime truth test of one exact compiler value (for example a boolean
    /// property read). The adapter owns the language syntax; consumers match
    /// the typed value against rule-declared semantics.
    Truthy {
        span: Span,
        operand: ConditionOperandFact,
    },
    Not {
        span: Span,
        operand: Box<ConditionExpressionFact>,
    },
    All {
        span: Span,
        operands: Vec<ConditionExpressionFact>,
    },
    Any {
        span: Span,
        operands: Vec<ConditionExpressionFact>,
    },
    Equality {
        span: Span,
        relation: ConditionEquality,
        left: ConditionOperandFact,
        right: ConditionOperandFact,
    },
    /// Runtime type predicate lowered by the owning language frontend.
    ///
    /// Type spellings remain language-owned (`str`, `string`, `String`,
    /// etc.); rulepack semantics decide which exact runtime types make a
    /// particular sink safe.
    TypeTest {
        span: Span,
        subject: ConditionOperandFact,
        type_name: String,
    },
    /// Compiler-proven collection membership. Method spellings, index syntax,
    /// and negation tokens remain owned by the language frontend.
    Membership {
        span: Span,
        subject: ConditionOperandFact,
        collection: ConditionOperandFact,
        then_contains: bool,
    },
}

impl ConditionExpressionFact {
    /// Exact parsed expression boundary represented by this node.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Atom { span }
            | Self::Truthy { span, .. }
            | Self::Not { span, .. }
            | Self::All { span, .. }
            | Self::Any { span, .. }
            | Self::Equality { span, .. }
            | Self::TypeTest { span, .. }
            | Self::Membership { span, .. } => *span,
        }
    }
}

/// Compiler-owned condition boundary for one parsed branch. Consumers use
/// `condition_span` to relate calls to the condition and `polarity` instead of
/// reparsing [`FlowEvent::Branch::condition`] rendering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchConditionFact {
    pub branch_span: Span,
    pub condition_span: Span,
    pub polarity: BranchConditionPolarity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<MembershipConditionFact>,
    /// Adapter-lowered boolean expression when that language has declared
    /// exact condition syntax support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<ConditionExpressionFact>,
}

/// Locate the condition fact for an exact branch span in the sorted file
/// table.
#[must_use]
pub fn branch_condition_fact_for_span(
    facts: &[BranchConditionFact],
    branch_span: Span,
) -> Option<&BranchConditionFact> {
    let key = |span: Span| (span.file.raw(), span.start, span.end);
    let wanted = key(branch_span);
    let index = facts.partition_point(|fact| key(fact.branch_span) < wanted);
    facts.get(index).filter(|fact| fact.branch_span == branch_span)
}

/// Compiler-owned value flow for a method-call receiver.
///
/// `call_span` is the exact span used by the sibling [`FlowEvent::Call`].
/// `value_flow` comes from the receiver's tree-sitter expression node, so
/// graph builders never need to tokenize the rendered `Call::receiver` or
/// callee name to recover nested calls and value operands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallReceiverFact {
    pub call_span: Span,
    pub receiver_span: Span,
    pub value_flow: ExpressionFlow,
    /// Compiler-resolved role of the receiver expression. Namespace/type
    /// qualifiers participate in call resolution but do not carry runtime
    /// data into the call as an implicit receiver value.
    #[serde(default, skip_serializing_if = "CallReceiverRole::is_value")]
    pub role: CallReceiverRole,
    /// Exact scalar receiver decoded by the owning language frontend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_value: Option<StaticScalarValue>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallReceiverRole {
    /// Ordinary runtime value receiver (`client.send(...)`).
    #[default]
    Value,
    /// Imported module/type namespace used only to qualify a callable
    /// (`pickle.loads(...)`, `fmt.Println(...)`).
    Namespace,
}

impl CallReceiverRole {
    #[must_use]
    pub const fn is_value(&self) -> bool {
        matches!(self, Self::Value)
    }
}

/// Compiler-owned value shape for one call argument.
///
/// `call_span` is the exact callee span used by the sibling
/// [`FlowEvent::Call`], while `argument_index` follows adapter-normalized
/// argument order. Consumers use `value_flow` for nested aggregate/object
/// semantics instead of reparsing [`CallArg::value_text`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallArgumentValueFact {
    pub call_span: Span,
    pub argument_index: usize,
    pub argument_span: Span,
    /// Callee span when the complete argument expression is one direct call
    /// (possibly through a transparent language wrapper). Nested calls do
    /// not populate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_call_span: Option<Span>,
    /// Adapter-lowered parameter bindings when the complete argument is an
    /// inline callback/lambda expression. Indices use the same flattened,
    /// source-ordered binding convention as [`Decl::params`]. API/provider
    /// identity is deliberately absent: rulepack transfer semantics decide
    /// whether a particular callback position receives source data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_callback_params: Vec<String>,
    pub value_flow: ExpressionFlow,
    /// Exact scalar value decoded by the owning language frontend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_value: Option<StaticScalarValue>,
    /// Exact scalar fields from a complete, spread-free aggregate structure.
    /// Unrelated dynamic leaves may be omitted, but dynamic keys, spreads,
    /// and duplicate paths reject the aggregate. Field names and literals
    /// come from Tree-sitter nodes; consumers must not parse `value_text`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_static_aggregate_fields: Vec<StaticAggregateFieldValue>,
    /// Complete positional aggregate lowered by the owning grammar. Each
    /// element is `Some` only when the adapter decoded an exact scalar;
    /// dynamic elements remain `None`. The outer option distinguishes a
    /// proven sequence from an expression that is not a sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_static_sequence_values: Option<Vec<Option<StaticScalarValue>>>,
}

/// One exact field in a compiler-lowered aggregate call argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAggregateFieldValue {
    /// Field path from the argument root. Nested aggregates use one segment
    /// per statically named field.
    pub path: Vec<String>,
    pub value: StaticScalarValue,
}

/// Language-decoded scalar literal used by exact semantic guards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum StaticScalarValue {
    String(String),
    Boolean(bool),
    Null,
}

/// Locate receiver-flow facts for a semantic call in the sorted file table.
#[must_use]
pub fn call_receiver_fact_for_span(facts: &[CallReceiverFact], call_span: Span) -> Option<&CallReceiverFact> {
    let key = |span: Span| (span.file.raw(), span.start, span.end);
    let wanted = key(call_span);
    let index = facts.partition_point(|fact| key(fact.call_span) < wanted);
    facts.get(index).filter(|fact| fact.call_span == call_span)
}

/// Locate one compiler-owned call-argument value fact.
#[must_use]
pub fn call_argument_value_fact(
    facts: &[CallArgumentValueFact],
    call_span: Span,
    argument_index: usize,
) -> Option<&CallArgumentValueFact> {
    let key = |span: Span, index: usize| (span.file.raw(), span.start, span.end, index);
    let wanted = key(call_span, argument_index);
    let index = facts.partition_point(|fact| key(fact.call_span, fact.argument_index) < wanted);
    facts
        .get(index)
        .filter(|fact| fact.call_span == call_span && fact.argument_index == argument_index)
}

/// Locate one exact assignment syntax fact in the sorted file-local fact
/// table emitted by [`crate::kit::extract_assignment_value_facts`].
#[must_use]
pub fn assignment_value_fact_for_span(
    facts: &[AssignmentValueFact],
    assignment_span: Span,
) -> Option<&AssignmentValueFact> {
    let key = |span: Span| (span.file.raw(), span.start, span.end);
    let wanted = key(assignment_span);
    let index = facts.partition_point(|fact| key(fact.assignment_span) < wanted);
    facts
        .get(index)
        .filter(|fact| fact.assignment_span == assignment_span)
}

/// Locate a compiler-proven finite-literal selection for one assignment.
///
/// Frontends sort these facts by their owning assignment/call span, so graph
/// lowering can preserve linear transfer complexity without scanning every
/// selection for every assignment in a large function.
#[must_use]
pub fn finite_literal_selection_for_assignment(
    facts: &[FiniteLiteralSelectionFact],
    assignment_span: Span,
) -> Option<&FiniteLiteralSelectionFact> {
    let key = |span: Span| (span.file.raw(), span.start, span.end);
    let wanted = key(assignment_span);
    let index = facts.partition_point(|fact| {
        key(fact
            .assignment_span
            .or(fact.call_span)
            .unwrap_or(fact.selection_span))
            < wanted
    });
    facts
        .get(index)
        .filter(|fact| fact.assignment_span == Some(assignment_span))
}

/// Render the exact RHS expression for one assignment from a sorted syntax
/// fact table without allocating a per-file lookup index.
#[must_use]
pub fn assignment_value_rendering<'a>(
    facts: &[AssignmentValueFact],
    assignment_span: Span,
    source_text: &'a str,
) -> Option<&'a str> {
    let fact = assignment_value_fact_for_span(facts, assignment_span)?;
    render_assignment_syntax_span(fact.value_span, assignment_span, source_text)
}

/// File-local lookup from an assignment event to the exact Tree-sitter RHS
/// expression selected by the language frontend. Consumers may inspect text
/// only through this index, so they cannot accidentally rediscover expression
/// boundaries by scanning an assignment statement for punctuation.
#[derive(Clone, Debug, Default)]
pub struct AssignmentValueIndex {
    spans: AHashMap<Span, AssignmentSyntaxSpans>,
}

#[derive(Copy, Clone, Debug)]
struct AssignmentSyntaxSpans {
    target: Option<Span>,
    value: Span,
}

impl AssignmentValueIndex {
    #[must_use]
    pub fn new(facts: &[AssignmentValueFact]) -> Self {
        let mut spans = AHashMap::with_capacity(facts.len());
        for fact in facts {
            spans
                .entry(fact.assignment_span)
                .or_insert(AssignmentSyntaxSpans {
                    target: fact.target_span,
                    value: fact.value_span,
                });
        }
        Self { spans }
    }

    #[must_use]
    pub fn value_span(&self, assignment_span: Span) -> Option<Span> {
        self.spans.get(&assignment_span).map(|spans| spans.value)
    }

    #[must_use]
    pub fn target_span(&self, assignment_span: Span) -> Option<Span> {
        self.spans.get(&assignment_span)?.target
    }

    /// Slice the source snapshot at the AST-selected RHS span. This is a
    /// zero-copy rendering of a compiler fact, not a text parser.
    #[must_use]
    pub fn rendering<'a>(&self, assignment_span: Span, source_text: &'a str) -> Option<&'a str> {
        let value_span = self.value_span(assignment_span)?;
        render_assignment_syntax_span(value_span, assignment_span, source_text)
    }

    /// Slice the source snapshot at the AST-selected target/pattern span.
    #[must_use]
    pub fn target_rendering<'a>(&self, assignment_span: Span, source_text: &'a str) -> Option<&'a str> {
        let target_span = self.target_span(assignment_span)?;
        render_assignment_syntax_span(target_span, assignment_span, source_text)
    }
}

fn render_assignment_syntax_span<'a>(
    syntax_span: Span,
    assignment_span: Span,
    source_text: &'a str,
) -> Option<&'a str> {
    if syntax_span.file != assignment_span.file
        || syntax_span.start < assignment_span.start
        || syntax_span.end > assignment_span.end
    {
        return None;
    }
    let start = usize::try_from(syntax_span.start).ok()?;
    let end = usize::try_from(syntax_span.end).ok()?;
    source_text
        .get(start..end)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclIndex {
    pub file: FileId,
    pub defs: Vec<Decl>,
    pub refs: Vec<Ref>,
    /// RHS-node spans for assignment-shaped nodes in this file's parsed tree.
    /// Kept file-local and flat so exact renderings remain zero-copy slices of
    /// the source snapshot rather than duplicated strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignment_values: Vec<AssignmentValueFact>,
    /// Parsed receiver-expression dependencies keyed by semantic call span.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_receivers: Vec<CallReceiverFact>,
    /// Parsed argument-expression value shapes keyed by semantic call span
    /// and adapter-normalized argument index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_argument_values: Vec<CallArgumentValueFact>,
    /// Complete static string maps decoded by the owning language frontend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_string_maps: Vec<StaticStringMapFact>,
    /// Exact language-owned string-composition shapes, keyed by their
    /// assignment/return container span.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub string_compositions: Vec<StringCompositionFact>,
    /// Finite literal-map selections decoded by the owning frontend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finite_literal_selections: Vec<FiniteLiteralSelectionFact>,
    /// Local character-substitution helper summaries decoded from syntax.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub character_substitutions: Vec<CharacterSubstitutionFact>,
    /// Exact local alphabet constraints lowered by the owning frontend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub character_constraints: Vec<CharacterConstraintFact>,
    /// Predicate-guarded value filters lowered by the owning frontend. Rules
    /// provide the predicate's security meaning; this IR contains syntax and
    /// dataflow proof only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guarded_value_filters: Vec<GuardedValueFilterFact>,
    /// Exact same-origin path summaries lowered by the owning frontend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub same_origin_path_constraints: Vec<SameOriginPathConstraintFact>,
    /// Complete runtime guard capabilities lowered by the owning frontend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compiler_guards: Vec<CompilerGuardFact>,
    /// Exact local dynamic-key filter summaries lowered by the frontend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_key_filters: Vec<DynamicKeyFilterFact>,
    /// Parsed branch-local type refinements keyed by their guarded arm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_type_narrowings: Vec<RuntimeTypeNarrowingFact>,
    /// Parsed branch-condition boundaries and polarity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub branch_conditions: Vec<BranchConditionFact>,
    /// Grammar-declared aggregate field layouts in this file. These are
    /// workspace-level type facts rather than function declarations, so they
    /// live beside the per-file declaration index and remain available for
    /// cross-file initializer resolution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregate_layouts: Vec<AggregateLayout>,
    /// Every string / char literal found in the file. Used by the `strings`
    /// browse command to classify and locate SQL / URL / shell strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<StringLiteral>,
    /// Every comment node found in the file. Used by the `comments`
    /// browse command to surface TODO/FIXME/SECURITY markers, doc
    /// comments, and commented-out code alongside the rest of the
    /// indexed facts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<Comment>,
}

/// One comment occurrence. `text` is the raw slice verbatim (keeping
/// the `//` / `#` / `/* */` markers) so downstream renderers can
/// preserve the original style; `kind` is a coarse classification
/// derived from the marker-stripped content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub span: Span,
    pub text: String,
    pub kind: CommentKind,
}

/// Coarse classification of a comment — cheap content heuristics so
/// reviewers can filter for the attention-grabbing ones without a
/// regex. `Generic` is the honest default.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommentKind {
    /// `// TODO: ...`, `# TODO`, `/* TODO */`.
    Todo,
    /// `FIXME`, `XXX`, `HACK`, `BUG`.
    Fixme,
    /// `SECURITY:`, `NOTE:` attention markers referring to security.
    Security,
    /// Python docstring / Rust doc-comment / JSDoc / KDoc.
    Doc,
    /// Commented-out code (contains `;`, `{`, `=`, function-call
    /// shape — best-effort heuristic).
    DisabledCode,
    /// Everything else.
    Generic,
}

impl CommentKind {
    /// Best-effort classification from the comment's body (markers
    /// already stripped). Conservative — `Generic` is the default.
    ///
    /// Attention markers (`SECURITY:`, `CVE-`, `TODO`, `FIXME`,
    /// `XXX`, `HACK`, `BUG`) win over the doc-comment classification
    /// so that a Rust `/// TODO:` or a JSDoc `/** FIXME */` still
    /// surfaces under `comments --kind todo|fixme|security`. Without
    /// this, doc-form attention markers were silently classified as
    /// `Doc` and invisible to the most common review sweeps.
    #[must_use]
    pub fn classify(body: &str, is_doc: bool) -> Self {
        let upper = body.trim_start().to_ascii_uppercase();
        // Check security first so a "TODO: SECURITY" still surfaces
        // via the more attention-grabbing tag.
        if upper.contains("SECURITY:")
            || upper.contains("CVE-")
            || upper.contains("XXX SECURITY")
            || upper.contains("VULN:")
            || upper.contains("VULNERAB")
            || upper.contains(" INJECTION")
            || upper.contains("TAINT")
            || upper.starts_with("SOURCE:")
            || upper.contains(" SOURCE:")
            || upper.starts_with("SINK:")
            || upper.contains(" SINK:")
            || upper.starts_with("SANITIZER:")
            || upper.contains(" SANITIZER:")
            || upper.starts_with("UNSANITIZED")
            || upper.contains(" UNSANITIZED")
        {
            return Self::Security;
        }
        if upper.starts_with("TODO") || upper.contains(" TODO:") || upper.contains(" TODO ") {
            return Self::Todo;
        }
        if upper.starts_with("FIXME")
            || upper.starts_with("XXX")
            || upper.starts_with("HACK")
            || upper.starts_with("BUG")
            || upper.contains(" FIXME")
            || upper.contains(" XXX")
            || upper.contains(" HACK")
            || upper.contains(" BUG")
        {
            return Self::Fixme;
        }
        if is_doc {
            return Self::Doc;
        }
        // Heuristic for commented-out code: contains a statement
        // terminator AND looks like it has program-like tokens.
        let trimmed = body.trim();
        let has_terminator = trimmed.ends_with(';') || trimmed.ends_with('{') || trimmed.ends_with('}');
        let has_assign_or_call = trimmed.contains('=') || (trimmed.contains('(') && trimmed.contains(')'));
        if has_terminator && has_assign_or_call {
            return Self::DisabledCode;
        }
        Self::Generic
    }
}

/// One string-literal occurrence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringLiteral {
    pub span: Span,
    pub text: String,
    pub category: StringCategory,
    /// Exact decoded scalar value when the owning language adapter can prove
    /// one from its Tree-sitter grammar. Interpolated strings and literal
    /// forms requiring unsupported escape decoding remain `None`; semantic
    /// consumers must never recover a value by trimming `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_value: Option<String>,
}

/// Rough, adapter-agnostic category derived from content heuristics. Never
/// claim more than the text actually suggests — `category: Generic` is the
/// honest default.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringCategory {
    Sql,
    Url,
    Shell,
    Path,
    Regex,
    Format,
    Generic,
}

impl StringCategory {
    /// Best-effort classification. Heuristic and intentionally conservative
    /// — false positives are worse than `Generic`.
    #[must_use]
    pub fn classify(text: &str) -> Self {
        let trimmed = text.trim_matches(|c: char| matches!(c, '"' | '\'' | '`')).trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("select ")
            || lower.starts_with("insert ")
            || lower.starts_with("update ")
            || lower.starts_with("delete ")
            || lower.starts_with("create table")
            || lower.contains(" from ") && lower.contains("select ")
        {
            return Self::Sql;
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.starts_with("ws://") {
            return Self::Url;
        }
        if trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../") {
            return Self::Path;
        }
        if trimmed.starts_with('^') && trimmed.ends_with('$') {
            return Self::Regex;
        }
        if trimmed.contains("{}") || trimmed.contains("%s") || trimmed.contains("%d") {
            return Self::Format;
        }
        if trimmed.contains(" | ") || trimmed.starts_with("cmd ") || trimmed.starts_with("sh -") {
            return Self::Shell;
        }
        Self::Generic
    }
}

/// Which consumers an `ImportSpec` is visible to.
///
/// The browse layer (`imports` command, `inspect --from`/`--to` chain-
/// filter tokens) only wants entries that are distinctly "this file is
/// importing from here". The resolver and security matcher want every
/// local binding they can resolve — including ES-module / CommonJS
/// shorthand destructures (`const { exec } = require("child_process")`)
/// whose local name is the only thing call sites reference, but whose
/// presence in browse output would broaden `--from X` filters
/// undesirably.
///
/// A single `ImportScope` field lets every consumer pick the
/// appropriate subset without the adapters having to emit two parallel
/// lists, and without a duplicate tree walk living next to
/// `parse_imports` just to build an alias map.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportScope {
    /// Standard visible import — shows up in `imports` browse, contributes
    /// to `inspect` `--from`/`--to` filter tokens, and resolves for call
    /// dispatch. The default.
    #[default]
    Module,
    /// Resolution-only binding — a local name bound by a destructuring
    /// shorthand / default-import form, or a synthetic adapter binding
    /// needed to resolve language/module conventions. These entries do
    /// not mean "this file imports this module" and must not appear as
    /// public import inventory rows. They still feed the resolver's
    /// alias map and the security matcher's `callee.attribute`
    /// expansion path.
    Local,
}

/// One adapter-emitted import/include/use/require fact.
///
/// `module` is the adapter-visible package or module target. It is
/// consumed directly by the security package gate
/// (`bonsai_security::pkg::import_matches_package`), so rulepack
/// `packages:` / `imports:` / `modules:` signals must name this same
/// surface rather than ecosystem metadata such as Maven artifact ids.
/// Aliases and imported symbols belong in `alias` and
/// `original_name`; do not fold them into `module`.
///
/// Supported adapters are pinned by the mega-flow contract test in
/// `crates/conformance/tests/architecture_invariants.rs`:
///
/// | Language | Fixture import form | Adapter `module` |
/// | --- | --- | --- |
/// | C | `#include <stdio.h>` | `stdio.h` |
/// | C++ | `#include "envelope.hpp"` | `envelope.hpp` |
/// | C# | `using Tasks = System.Threading.Tasks;` | `System.Threading.Tasks` |
/// | Dart | `import 'dart:io';` | `dart:io` |
/// | Elixir | `alias Mega.Storage, as: Store` | `Mega.Storage` |
/// | Erlang | `-include("envelope.hrl").` / module import | `envelope.hrl` / `storage` |
/// | Go | `import execpkg "os/exec"` | `os/exec` |
/// | Java | `import jakarta.servlet.http.HttpServletRequest;` | `jakarta.servlet.http.HttpServletRequest` |
/// | JavaScript | `const { persist: persistEnvelope } = require("./storage")` | `./storage` |
/// | Kotlin | `import jakarta.servlet.http.HttpServletRequest` | `jakarta.servlet.http.HttpServletRequest` |
/// | Lua | `local Executor = require("executor")` | `executor` |
/// | Objective-C | `#import <Foundation/Foundation.h>` | `Foundation/Foundation.h` |
/// | Perl | `use CGI;` | `CGI` |
/// | PHP | `use Storage as Store;` | `Storage` |
/// | Python | `from flask import request` | `flask` |
/// | Ruby | `require_relative "pipeline"` | `pipeline` |
/// | Rust | `use std::io::{self, BufRead};` | `std::io` |
/// | Scala | `import mega.Storage as Store` | `mega` |
/// | Swift | `import Foundation` | `Foundation` |
/// | TypeScript | `import { persist as persistEnvelope } from "./storage"` | `./storage` |
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSpec {
    pub span: Span,
    pub module: String,
    pub alias: Option<String>,
    pub is_wildcard: bool,
    /// Original symbol name when `alias` renames an individual symbol
    /// rather than (or in addition to) the whole module. Captures the
    /// `y` in `from x import y as z`, the `a` in `import { a as b }`,
    /// `use x::y as z`, Scala's `{a => b}`, PHP's `use X\Service as S`,
    /// and so on. `None` for module-only aliases (`import os as o`)
    /// where downstream call resolution works via the short-tail name
    /// anyway (`o.system()` → `system`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    /// Visibility scope — `Module` by default, `Local` for
    /// destructuring shorthand / default-import bindings that
    /// resolvers care about but browse output should hide. See
    /// [`ImportScope`].
    #[serde(default, skip_serializing_if = "ImportScope::is_module")]
    pub scope: ImportScope,
}

impl ImportScope {
    #[must_use]
    pub fn is_module(&self) -> bool {
        matches!(self, ImportScope::Module)
    }
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, ImportScope::Local)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportIndex {
    pub file: FileId,
    pub imports: Vec<ImportSpec>,
}

impl CompilerBrowseHeader {
    /// Project exact file-local browse candidates from canonical adapter IR.
    #[must_use]
    pub fn from_indexes(declarations: Option<&DeclIndex>, imports: Option<&ImportIndex>) -> Self {
        fn add(groups: &mut ahash::AHashMap<String, ahash::AHashSet<String>>, kind: &str, value: &str) {
            let group = groups.entry(kind.to_string()).or_default();
            let raw = value.trim().to_lowercase();
            if !raw.is_empty() {
                group.insert(raw);
            }
            group.extend(
                value
                    .split(|character: char| {
                        !(character.is_ascii_alphanumeric()
                            || matches!(character, '_' | '$' | '@' | ':' | '.'))
                    })
                    .filter(|part| !part.is_empty())
                    .map(str::to_lowercase),
            );
        }

        fn collect_flow(
            groups: &mut ahash::AHashMap<String, ahash::AHashSet<String>>,
            events: &[FlowEvent],
            enclosing: &str,
        ) {
            for event in events {
                match event {
                    FlowEvent::Call { name, args, .. } => {
                        add(groups, "call", name);
                        add(groups, "call", enclosing);
                        for argument in args {
                            add(groups, "arg", &argument.value_text);
                            add(groups, "arg", enclosing);
                            if let Some(name) = argument.name.as_deref() {
                                add(groups, "arg", name);
                                add(groups, "arg", &format!("{name}={}", argument.value_text));
                            }
                            if let Some(place) = argument.place.as_deref() {
                                add(groups, "arg", place);
                            }
                            for source in &argument.source_names {
                                add(groups, "arg", source);
                            }
                        }
                    }
                    FlowEvent::Assign {
                        target,
                        source_name,
                        source_call,
                        source_call_args,
                        source_names,
                        ..
                    } => {
                        add(groups, "var", target);
                        add(groups, "var", enclosing);
                        let display_source = source_name
                            .as_deref()
                            .or(source_call.as_deref())
                            .or_else(|| source_names.first().map(String::as_str));
                        if let Some(source) = display_source {
                            add(groups, "var", source);
                            add(groups, "var", &format!("{target} = {source}"));
                        }
                        if let Some(call) = source_call {
                            add(groups, "call", call);
                            add(groups, "call", enclosing);
                            for argument in source_call_args {
                                add(groups, "arg", argument);
                            }
                        }
                        for source in source_names {
                            add(groups, "ref-read", source);
                            add(groups, "ref-read", enclosing);
                        }
                    }
                    FlowEvent::Branch {
                        then_events,
                        else_events,
                        ..
                    } => {
                        collect_flow(groups, then_events, enclosing);
                        collect_flow(groups, else_events, enclosing);
                    }
                    FlowEvent::Loop { body, .. }
                    | FlowEvent::Defer { body, .. }
                    | FlowEvent::Using { body, .. } => collect_flow(groups, body, enclosing),
                    FlowEvent::Try {
                        body,
                        catch_events,
                        finally_events,
                        ..
                    } => {
                        collect_flow(groups, body, enclosing);
                        collect_flow(groups, catch_events, enclosing);
                        collect_flow(groups, finally_events, enclosing);
                    }
                    _ => {}
                }
            }
        }

        fn enclosing_function(index: &DeclIndex, span: Span) -> Option<&str> {
            index
                .defs
                .iter()
                .filter(|declaration| {
                    matches!(
                        declaration.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    ) && declaration.span.start <= span.start
                        && span.end <= declaration.span.end
                })
                .min_by_key(|declaration| declaration.span.end.saturating_sub(declaration.span.start))
                .map(|declaration| declaration.name.as_str())
        }

        let mut groups = ahash::AHashMap::<String, ahash::AHashSet<String>>::default();
        if let Some(index) = declarations {
            for declaration in &index.defs {
                let kind = format!("{:?}", declaration.kind).to_lowercase();
                add(&mut groups, &kind, &declaration.name);
                if let Some(qualified) = declaration.qualified_name.as_deref() {
                    add(&mut groups, &kind, qualified);
                }
                for parameter in &declaration.params {
                    add(&mut groups, &kind, parameter);
                }
                for operation in operations_from_flow_events(&declaration.flow_events) {
                    add(&mut groups, "operation", operation.kind.as_str());
                    add(&mut groups, "operation", &declaration.name);
                    if let Some(target) = operation.target.as_deref() {
                        add(&mut groups, "operation", target);
                    }
                    if let Some(detail) = operation.detail.as_deref() {
                        add(&mut groups, "operation", detail);
                    }
                    for operand in operation.operands {
                        add(&mut groups, "operation", &operand.name);
                        add(&mut groups, "operation", operand.role.as_str());
                        add(
                            &mut groups,
                            "operation",
                            &format!("{}:{}", operand.role.as_str(), operand.name),
                        );
                    }
                }
                collect_flow(&mut groups, &declaration.flow_events, &declaration.name);
            }
            for reference in &index.refs {
                let kind = match reference.kind {
                    RefKind::Read => "ref-read",
                    RefKind::Write => "ref-write",
                    RefKind::Call => "ref-call",
                    RefKind::Decorator => "ref-decorator",
                    _ => "ref",
                };
                add(&mut groups, kind, &reference.name);
            }
            for string in &index.strings {
                add(&mut groups, "string", &string.text);
                add(
                    &mut groups,
                    "string",
                    &format!("{:?}", string.category).to_lowercase(),
                );
                if let Some(function) = enclosing_function(index, string.span) {
                    add(&mut groups, "string", function);
                }
            }
            for comment in &index.comments {
                add(&mut groups, "comment", &comment.text);
                add(
                    &mut groups,
                    "comment",
                    &format!("{:?}", comment.kind).to_lowercase(),
                );
                if let Some(function) = enclosing_function(index, comment.span) {
                    add(&mut groups, "comment", function);
                }
            }
        }
        if let Some(index) = imports {
            for import in &index.imports {
                let kind = if import.alias.is_some() {
                    "import-alias"
                } else {
                    "import"
                };
                add(&mut groups, kind, &import.module);
                if let Some(alias) = import.alias.as_deref() {
                    add(&mut groups, kind, alias);
                }
                if let Some(original) = import.original_name.as_deref() {
                    add(&mut groups, kind, original);
                }
            }
        }

        let mut groups = groups
            .into_iter()
            .map(|(kind, terms)| {
                let mut terms = terms.into_iter().collect::<Vec<_>>();
                terms.sort_unstable();
                CompilerBrowseTermGroup { kind, terms }
            })
            .collect::<Vec<_>>();
        groups.sort_unstable_by(|left, right| left.kind.cmp(&right.kind));
        Self { groups }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedConstruct {
    pub span: Span,
    pub note: String,
    pub precision: Precision,
}

#[cfg(test)]
mod compiler_attribution_tests {
    use super::*;

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(4), start, end)
    }

    fn decl(kind: DeclKind, declaration_span: Span, flow_events: Vec<FlowEvent>) -> Decl {
        Decl {
            symbol: SymbolId::new(u32::try_from(declaration_span.start).expect("test symbol")),
            kind,
            name: "fixture".to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: declaration_span,
            name_span: declaration_span,
            visibility: Visibility::Private,
            parent: None,
            body_span: Some(declaration_span),
            flow_events,
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
            is_variadic: false,
        }
    }

    #[test]
    fn compiler_attribution_projects_nested_adapter_ir_without_text_tokenization() {
        let direct_call = span(10, 18);
        let assignment_call = span(30, 42);
        let function_span = span(1, 80);
        let index = DeclIndex {
            file: FileId::new(4),
            defs: vec![
                decl(
                    DeclKind::Function,
                    function_span,
                    vec![
                        FlowEvent::Call {
                            span: direct_call,
                            name: "send".to_string(),
                            receiver: Some("repo.client".to_string()),
                            receiver_types: vec!["Repository".to_string()],
                            call_kind: CallKind::Method,
                            args: vec![CallArg {
                                span: span(15, 17),
                                passing_mode: ArgumentPassingMode::Value,
                                name: None,
                                value_text: "payload".to_string(),
                                place: Some("payload".to_string()),
                                source_names: vec!["payload".to_string()],
                            }],
                        },
                        FlowEvent::Branch {
                            span: span(19, 29),
                            condition: None,
                            then_events: vec![FlowEvent::Return {
                                span: span(21, 27),
                                value_text: Some("payload".to_string()),
                                value_name: Some("payload".to_string()),
                                value_flow: ExpressionFlow::from_place("payload"),
                            }],
                            else_events: Vec::new(),
                        },
                        FlowEvent::Assign {
                            span: assignment_call,
                            target: "saved".to_string(),
                            source_name: Some("payload".to_string()),
                            source_call: Some("transform".to_string()),
                            source_call_args: vec!["payload".to_string(), "x + y".to_string()],
                            source_names: vec!["fallback".to_string()],
                            declares_new_binding: true,
                            value_kind: Some(AssignValueKind::CallResult),
                        },
                    ],
                ),
                // Non-callable declarations must not manufacture function
                // attribution even if a malformed fixture gives them events.
                decl(
                    DeclKind::Class,
                    span(90, 120),
                    vec![FlowEvent::Call {
                        span: span(100, 110),
                        name: "ignored".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        args: Vec::new(),
                    }],
                ),
            ],
            call_receivers: vec![CallReceiverFact {
                call_span: direct_call,
                receiver_span: span(10, 14),
                value_flow: ExpressionFlow {
                    place: Some("repo.client".to_string()),
                    source_names: vec!["repo".to_string()],
                    aggregate_fields: vec![ExpressionField {
                        name: "nested".to_string(),
                        value_span: None,
                        value: ExpressionFlow::from_place("nested.value"),
                    }],
                    ..ExpressionFlow::default()
                },
                role: CallReceiverRole::Value,
                static_value: None,
            }],
            ..DeclIndex::default()
        };

        let projected = CompilerAttribution::from_decl_index(&index);
        assert_eq!(projected.file, FileId::new(4));
        assert_eq!(projected.functions.len(), 1);
        let function = projected
            .function_at_span(function_span)
            .expect("function projection");
        assert_eq!(function.calls.len(), 2);
        assert_eq!(function.calls[0].name, "send");
        assert_eq!(
            function.calls[0].receiver_source_names,
            ["nested.value", "repo", "repo.client"]
        );
        assert_eq!(function.return_spans, [span(21, 27)]);
        assert_eq!(function.writes.len(), 1);
        assert_eq!(function.writes[0].source_names, ["payload", "fallback"]);
        assert_eq!(function.calls[1].name, "transform");
        assert_eq!(function.calls[1].args[0].place.as_deref(), Some("payload"));
        assert!(
            function.calls[1].args[1].source_names.is_empty(),
            "rendered compound text must not be split into invented carriers"
        );
        assert!(projected.function_at_span(span(90, 120)).is_none());
    }
}

#[cfg(test)]
mod operation_tests {
    use super::*;

    fn span(start: u64) -> Span {
        Span::new(FileId::new(0), start, start + 1)
    }

    fn kinds(ops: &[Operation]) -> Vec<OperationKind> {
        ops.iter().map(|op| op.kind).collect()
    }

    #[test]
    fn comment_security_classification_covers_review_markers() {
        for text in [
            "source: user input",
            "sink: SQL injection",
            "flows to command injection",
            "VULN: insecure deserialization",
            "unsanitized request parameter",
        ] {
            assert_eq!(
                CommentKind::classify(text, false),
                CommentKind::Security,
                "{text}"
            );
        }
    }

    #[test]
    fn comment_security_classification_does_not_match_generic_source_word() {
        assert_eq!(
            CommentKind::classify("source file generated by build", false),
            CommentKind::Generic
        );
    }

    #[test]
    fn operations_capture_assignment_reads_writes_and_place_shapes() {
        let ops = operations_from_flow_events(&[FlowEvent::Assign {
            span: span(10),
            target: "user.name".to_string(),
            source_name: Some("payload[0]".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["request.body".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        }]);

        assert!(ops.iter().any(|op| {
            op.kind == OperationKind::Write
                && op.target.as_deref() == Some("user.name")
                && op
                    .operands
                    .iter()
                    .any(|operand| operand.name == "payload[0]" && operand.role == OperationOperandRole::Read)
        }));
        assert!(ops
            .iter()
            .any(|op| op.kind == OperationKind::Read && op.target.as_deref() == Some("request.body")));
        assert!(ops
            .iter()
            .any(|op| op.kind == OperationKind::FieldAccess && op.target.as_deref() == Some("user.name")));
        assert!(ops
            .iter()
            .any(|op| op.kind == OperationKind::Index && op.target.as_deref() == Some("payload[0]")));
    }

    #[test]
    fn operations_capture_calls_arguments_and_allocations() {
        let ops = operations_from_flow_events(&[FlowEvent::Call {
            span: span(20),
            name: "Widget".to_string(),
            receiver: Some("factory".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(21),
                name: None,
                value_text: "config".to_string(),
                place: Some("opts.value".to_string()),
                source_names: vec!["config".to_string()],
            }],
        }]);

        assert!(ops.iter().any(|op| {
            op.kind == OperationKind::Call
                && op.target.as_deref() == Some("Widget")
                && op.detail.as_deref() == Some("constructor")
        }));
        assert!(ops
            .iter()
            .any(|op| op.kind == OperationKind::Allocate && op.target.as_deref() == Some("Widget")));
        assert!(ops
            .iter()
            .any(|op| op.kind == OperationKind::Read && op.target.as_deref() == Some("config")));
        assert!(ops
            .iter()
            .any(|op| op.kind == OperationKind::FieldAccess && op.target.as_deref() == Some("opts.value")));
    }

    #[test]
    fn operations_recurse_through_structured_flow_and_lifecycle() {
        let ops = operations_from_flow_events(&[FlowEvent::Branch {
            span: span(30),
            condition: Some("allowed".to_string()),
            then_events: vec![FlowEvent::Try {
                span: span(31),
                body: vec![FlowEvent::Lifecycle {
                    span: span(32),
                    name: "fd".to_string(),
                    transition: "closed".to_string(),
                }],
                catch_events: vec![FlowEvent::Throw {
                    span: span(33),
                    value_name: Some("err".to_string()),
                    thrown_type: Some("Error".to_string()),
                }],
                finally_events: vec![FlowEvent::Return {
                    span: span(34),
                    value_text: None,
                    value_name: Some("result".to_string()),
                    value_flow: ExpressionFlow::from_place("result"),
                }],
                catch_param: Some("err".to_string()),
                catch_types: Vec::new(),
            }],
            else_events: Vec::new(),
        }]);

        let observed = kinds(&ops);
        for expected in [
            OperationKind::BranchCondition,
            OperationKind::Release,
            OperationKind::CatchBinding,
            OperationKind::Throw,
            OperationKind::Return,
        ] {
            assert!(
                observed.contains(&expected),
                "missing {expected:?} in {observed:?}"
            );
        }
    }

    #[test]
    fn operations_capture_yield_value_reads_conservatively() {
        let ops = operations_from_flow_events(&[
            FlowEvent::Yield {
                span: span(40),
                value_text: Some("payload[0]".to_string()),
                value_flow: ExpressionFlow::from_place("payload[0]"),
            },
            FlowEvent::Yield {
                span: span(50),
                value_text: Some("left + right".to_string()),
                value_flow: ExpressionFlow::from_source_names(vec!["left".to_string(), "right".to_string()]),
            },
        ]);

        assert!(ops
            .iter()
            .any(|op| { op.kind == OperationKind::Yield && op.target.as_deref() == Some("payload[0]") }));
        assert!(ops.iter().any(|op| {
            op.kind == OperationKind::Read
                && op.target.as_deref() == Some("payload[0]")
                && op.detail.as_deref() == Some("yield_value")
        }));
        assert!(ops
            .iter()
            .any(|op| { op.kind == OperationKind::Index && op.target.as_deref() == Some("payload[0]") }));
        for operand in ["left", "right"] {
            assert!(ops.iter().any(|op| {
                op.kind == OperationKind::Read
                    && op.target.as_deref() == Some(operand)
                    && op.detail.as_deref() == Some("yield_value")
            }));
        }
    }
}
