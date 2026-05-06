//! Per-language capability declarations.

use serde::{Deserialize, Serialize};

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
}

impl LanguageCapabilities {
    /// Useful baseline: no claims at all. Adapters can override individual
    /// fields by constructing from this and mutating.
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
        }
    }
}
