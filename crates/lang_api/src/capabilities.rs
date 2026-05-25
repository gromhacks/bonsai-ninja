//! Per-language capability declarations.

use serde::{Deserialize, Serialize};

/// Sentinel for mature adapters whose language has no super-receiver
/// token. The string is intentionally not a valid identifier tail in
/// any supported grammar; it lets adapters distinguish "no token" from
/// the legacy empty-slice fallback.
pub const NO_SUPER_RECEIVER_TOKENS: &[&str] = &["<no-super-receiver>"];

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    /// The adapter handles this construct precisely.
    Exact,
    /// The adapter handles the common case; rare forms emit diagnostics.
    Partial,
    /// The construct is ignored; reachable uses degrade to `Precision::Unknown`.
    Unsupported,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LanguageCapabilities {
    pub modules: CapabilityLevel,
    pub generics: CapabilityLevel,
    pub macros: CapabilityLevel,
    pub dynamic_dispatch: CapabilityLevel,
    pub exceptions: CapabilityLevel,
    pub async_await: CapabilityLevel,
    pub coroutines: CapabilityLevel,
    pub reflection: CapabilityLevel,
    pub ffi: CapabilityLevel,
    pub pattern_matching: CapabilityLevel,
    /// Adapter/index pipeline emits static receiver type facts for
    /// method-call receivers. This lets downstream resolution use
    /// semantic class/type identity instead of receiver-name lists.
    pub receiver_types: CapabilityLevel,
    /// Receiver names that the language treats as aliases for an
    /// export. Used by the call graph to expand an alias-tail to the
    /// set of fully-qualified callee shapes when resolving cross-file
    /// references. JS/TS expose `exports.<name>` and
    /// `module.exports.<name>`; most other languages declare nothing.
    /// Empty by default; an adapter that wants to participate in
    /// cross-module export resolution declares the full set.
    pub module_export_aliases: &'static [&'static str],
    /// Method names this language uses for constructors (e.g.
    /// Python's `__init__`, Rust's `new`, Java/C++/C# class-named
    /// constructors). When empty, callers fall back to the
    /// cross-language `bonsai_common::CONSTRUCTOR_METHOD_NAMES`
    /// allowlist for backwards-compatibility — adapters should
    /// override with the narrowest correct set so cross-language
    /// fallbacks aren't relied on once the adapter is mature.
    pub constructor_method_names: &'static [&'static str],
    /// Receiver tokens that resolve to "the supertype's method"
    /// (e.g. JS `super`, PHP `parent`, Python `super()` is a call
    /// not a token). Empty defaults fall through to the cross-
    /// language `bonsai_common::SUPER_RECEIVER_TOKENS` for legacy
    /// adapters. Mature adapters whose language has no such token
    /// should set [`NO_SUPER_RECEIVER_TOKENS`].
    pub super_receiver_tokens: &'static [&'static str],
    /// Receiver tokens that bind to the enclosing instance/class
    /// (e.g. `self`, `this`, `me`). Empty defaults fall through to
    /// the cross-language `bonsai_common::IMPLICIT_RECEIVER_TOKENS`.
    pub implicit_receiver_tokens: &'static [&'static str],
}

impl LanguageCapabilities {
    /// Useful baseline: no claims at all. Adapters can override individual
    /// fields by constructing from this and mutating.
    /// Effective constructor method names: the adapter's slice when
    /// non-empty, otherwise the cross-language fallback in
    /// `bonsai_common::CONSTRUCTOR_METHOD_NAMES`. Adapters should
    /// override `constructor_method_names` with the narrowest
    /// correct set so the fallback only fires for not-yet-migrated
    /// adapters.
    #[must_use]
    pub fn effective_constructor_method_names(&self) -> &'static [&'static str] {
        if self.constructor_method_names.is_empty() {
            bonsai_common::CONSTRUCTOR_METHOD_NAMES
        } else {
            self.constructor_method_names
        }
    }

    /// Effective super-receiver tokens with the same fall-through
    /// shape as `effective_constructor_method_names`.
    #[must_use]
    pub fn effective_super_receiver_tokens(&self) -> &'static [&'static str] {
        if self.super_receiver_tokens.is_empty() {
            bonsai_common::SUPER_RECEIVER_TOKENS
        } else {
            self.super_receiver_tokens
        }
    }

    /// Effective implicit-receiver tokens.
    #[must_use]
    pub fn effective_implicit_receiver_tokens(&self) -> &'static [&'static str] {
        if self.implicit_receiver_tokens.is_empty() {
            bonsai_common::IMPLICIT_RECEIVER_TOKENS
        } else {
            self.implicit_receiver_tokens
        }
    }

    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            modules: CapabilityLevel::Unsupported,
            generics: CapabilityLevel::Unsupported,
            macros: CapabilityLevel::Unsupported,
            dynamic_dispatch: CapabilityLevel::Unsupported,
            exceptions: CapabilityLevel::Unsupported,
            async_await: CapabilityLevel::Unsupported,
            coroutines: CapabilityLevel::Unsupported,
            reflection: CapabilityLevel::Unsupported,
            ffi: CapabilityLevel::Unsupported,
            pattern_matching: CapabilityLevel::Unsupported,
            receiver_types: CapabilityLevel::Unsupported,
            module_export_aliases: &[],
            constructor_method_names: &[],
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
        }
    }

    #[must_use]
    pub const fn partial_baseline() -> Self {
        Self {
            modules: CapabilityLevel::Partial,
            generics: CapabilityLevel::Partial,
            macros: CapabilityLevel::Unsupported,
            dynamic_dispatch: CapabilityLevel::Partial,
            exceptions: CapabilityLevel::Partial,
            async_await: CapabilityLevel::Partial,
            // The kit recognizes the six yield grammar shapes
            // (`yield`, `yield_statement`, `yield_expression`,
            // `yield_from_expression`, `co_yield_*`) and emits
            // `FlowEvent::Yield`. The interprocedural engine treats
            // yielded values as return-equivalent for summary
            // construction (see `summary_impl.rs::Yield` handler) so
            // taint flowing into a yielded expression is tracked.
            // Cross-process generator-state propagation is still out of
            // scope, so `Partial` (not `Exact`).
            coroutines: CapabilityLevel::Partial,
            reflection: CapabilityLevel::Unsupported,
            ffi: CapabilityLevel::Unsupported,
            pattern_matching: CapabilityLevel::Partial,
            receiver_types: CapabilityLevel::Unsupported,
            module_export_aliases: &[],
            constructor_method_names: &[],
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
        }
    }
}
