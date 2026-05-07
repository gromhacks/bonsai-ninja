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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Function,
    Method,
    Constructor,
    Macro,
    Indirect,
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
    /// Keyword-argument name (Python / Ruby / C# named args). `None` for positional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The argument's text verbatim. If it looks like a bare identifier
    /// referring to a function or lambda, the tracer uses it to resolve
    /// higher-order callback calls.
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
        if upper.contains("SECURITY:") || upper.contains("CVE-") || upper.contains("XXX SECURITY") {
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
    /// shorthand / default-import form whose presence would add noise to
    /// browse output. Still feeds the resolver's alias map and the
    /// security matcher's `callee.attribute` expansion path.
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
