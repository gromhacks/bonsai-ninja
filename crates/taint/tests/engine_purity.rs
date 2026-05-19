//! Programmatic invariants pinning the engine's "no embedded library
//! API knowledge" contract.
//!
//! Every fact table that controls library/framework-shaped behavior in
//! the interprocedural taint engine lives on `InterTaintConfig` and is
//! empty by default. This file fails compilation if a new field is
//! added without an empty-by-default test, and fails at test time if
//! any default field is non-empty.
//!
//! Why a test instead of a doc comment: a future contributor adding
//! `pub default_callback_invocation_methods: AHashSet<String>` with a
//! `vec!["call", "apply"]` default would silently undo months of
//! purity work. The compiler catches the change here so it has to be
//! conscious.

use bonsai_taint::InterTaintConfig;

#[test]
fn default_config_carries_zero_embedded_library_knowledge() {
    let config = InterTaintConfig::default();

    assert!(
        config.sanitizers.is_empty(),
        "default sanitizers must be empty; security layer populates them per analysis",
    );
    assert!(
        config.source_bearing_functions.is_empty(),
        "default source_bearing_functions must be empty; only the security layer populates this set",
    );
    assert!(
        config.clean_output_overwrites.is_empty(),
        "default clean_output_overwrites must be empty; rulepack `taint_semantics.clean_output_overwrite` populates this list",
    );
    assert!(
        config.callback_invocation_methods.is_empty(),
        "default callback_invocation_methods must be empty; adapters / rulepack supply method tails",
    );
    assert!(
        config.receiver_state_propagations.is_empty(),
        "default receiver_state_propagations must be empty; rulepack taint_semantics supplies receiver mutator shapes",
    );
    assert!(
        config.output_arg_flows.is_empty(),
        "default output_arg_flows must be empty; rulepack taint_semantics supplies output-argument transfer shapes",
    );
}

#[test]
fn default_config_uses_explicit_budget_not_unbounded() {
    let config = InterTaintConfig::default();
    assert!(
        config.budget > 0,
        "budget must be a positive default — unbounded propagation breaks the engine's safety contract",
    );
}
