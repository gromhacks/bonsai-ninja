//! Per-language capability declarations.

use serde::{Deserialize, Serialize};

/// Empty constructor-name vocabulary for languages whose constructors are
/// represented exclusively by constructor grammar nodes or class identity.
///
/// This is an empty slice, not a sentinel spelling: downstream resolution
/// must never infer language semantics from an invented identifier.
pub const NO_CONSTRUCTOR_METHOD_NAMES: &[&str] = &[];

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    /// The adapter has a closed static model for this construct.
    Exact,
    /// The adapter emits proven static evidence for recognized forms;
    /// unrecognized forms stay diagnostic/incomplete and must not be
    /// widened into public findings.
    Partial,
    /// The adapter has no static model for this construct; rules that
    /// require it should be rejected or treated as not applicable.
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
    /// Every source-level field/property projection is lowered to a concrete
    /// `Place` fact. Sink-oriented IDG builds may use those facts as complete
    /// sparse field-demand roots; adapters that leave call-shaped or pattern
    /// projections implicit must keep this false.
    pub field_places_complete: bool,
    /// Receiver names that the language treats as aliases for an
    /// export. Used by the call graph to expand an alias-tail to the
    /// set of fully-qualified callee shapes when resolving cross-file
    /// references. JS/TS expose `exports.<name>` and
    /// `module.exports.<name>`; most other languages declare nothing.
    /// Empty by default; an adapter that wants to participate in
    /// cross-module export resolution declares the full set.
    pub module_export_aliases: &'static [&'static str],
    /// Method names this language's grammar uses for constructors when the
    /// adapter cannot express the construct as [`DeclKind::Constructor`].
    /// Empty means there is no method-name form. There is deliberately no
    /// cross-language fallback.
    pub constructor_method_names: &'static [&'static str],
    /// A bare call expression may denote construction when semantic name
    /// resolution proves that its callee is a class (for example Python's
    /// `Widget(...)`). The call graph still requires exact scoped class
    /// identity; this capability only describes the grammar ambiguity and
    /// never enables capitalization-based inference.
    pub bare_call_constructor_syntax: bool,
    /// Receiver spellings that the adapter's syntax lowering resolves to
    /// "the supertype's method" (e.g. JS `super`, PHP `parent`, or the
    /// normalized Python call receiver `super()`). Empty means the language
    /// has no such syntax; there is deliberately no cross-language fallback.
    pub super_receiver_tokens: &'static [&'static str],
    /// Receiver tokens that bind to the enclosing instance/class
    /// (e.g. Ruby `self`, Java `this`). Empty means the grammar has no
    /// implicit receiver token. Explicit receiver parameters such as
    /// Python's first method parameter, Go's receiver declaration, and Rust's
    /// `self_parameter` are represented by `Decl::receiver_param_index`, not
    /// by this inventory.
    pub implicit_receiver_tokens: &'static [&'static str],
}

impl LanguageCapabilities {
    /// Useful baseline: no claims at all. Adapters can override individual
    /// fields by constructing from this and mutating.
    /// Adapter-owned constructor method spellings. The `effective_` name is
    /// retained for API compatibility; empty means no method-name form.
    #[must_use]
    pub fn effective_constructor_method_names(&self) -> &'static [&'static str] {
        self.constructor_method_names
    }

    /// Adapter-owned super-receiver spellings. The `effective_` name is kept
    /// for API compatibility; unlike constructor names, this never falls back
    /// to a cross-language spelling inventory.
    #[must_use]
    pub fn effective_super_receiver_tokens(&self) -> &'static [&'static str] {
        self.super_receiver_tokens
    }

    /// Adapter-owned implicit-receiver spellings, with empty meaning none.
    #[must_use]
    pub fn effective_implicit_receiver_tokens(&self) -> &'static [&'static str] {
        self.implicit_receiver_tokens
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
            field_places_complete: false,
            module_export_aliases: &[],
            constructor_method_names: &[],
            bare_call_constructor_syntax: false,
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
            field_places_complete: false,
            module_export_aliases: &[],
            constructor_method_names: &[],
            bare_call_constructor_syntax: false,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LanguageCapabilities;

    #[test]
    fn empty_receiver_capabilities_mean_no_receiver_syntax() {
        let capabilities = LanguageCapabilities::unsupported();
        assert!(capabilities.effective_super_receiver_tokens().is_empty());
        assert!(capabilities.effective_implicit_receiver_tokens().is_empty());
    }
}
