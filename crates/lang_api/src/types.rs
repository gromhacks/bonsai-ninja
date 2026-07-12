//! Shared declaration + import types used by adapters.
//!
//! These types are the contract between adapters and the core engine. Keep
//! them minimal: every field costs every adapter.

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
    /// type, Scala `: T`, Solidity `returns (T)`). Empty for
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
        let normalized = place.replace("->", ".").replace("::", ".");
        let mut parts = normalized
            .split('.')
            .map(str::trim)
            .filter(|part| !part.is_empty());
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
        /// Normalized source text of the branch condition when the
        /// adapter can identify one. This is intentionally textual:
        /// consumers only use it for small, language-neutral facts
        /// such as `flag`, `!flag`, `flag == 0`, or literal booleans.
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
    Indirect,
    /// Language-level channel send lowered from a dedicated AST node.
    ChannelSend,
}

impl CallKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CallKind::Function => "function",
            CallKind::Method => "method",
            CallKind::Constructor => "constructor",
            CallKind::Macro => "macro",
            CallKind::Indirect => "indirect",
            CallKind::ChannelSend => "channel_send",
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
    /// RHS is a compound expression (member access, binary op,
    /// template literal, ternary, conditional, …). Engine
    /// tokenises identifiers and bridges every carrier.
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
    place.contains('.') || place.contains("::") || place.contains("->")
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclIndex {
    pub file: FileId,
    pub defs: Vec<Decl>,
    pub refs: Vec<Ref>,
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
/// | Solidity | `import {Pipeline as FlowPipeline} from "./Pipeline.sol";` | `./Pipeline.sol` |
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedConstruct {
    pub span: Span,
    pub note: String,
    pub precision: Precision,
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
