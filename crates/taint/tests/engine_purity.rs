//! Programmatic invariants pinning the engine's "no embedded library
//! API knowledge" contract.
//!
//! Every fact table that controls library/framework-shaped behavior in
//! the IDG query surface lives on `InterTaintConfig` and is
//! empty by default. The graph engine consumes AST/resolver facts; only
//! explicit rule/config data may add external API transfer semantics.
//!
//! The compiler catches any new non-empty transfer default here so adding
//! embedded library behavior must be a conscious review decision.

use bonsai_taint::InterTaintConfig;

#[test]
fn default_config_carries_zero_embedded_library_knowledge() {
    let config = InterTaintConfig::default();

    assert!(
        config.clean_output_overwrites.is_empty(),
        "default clean_output_overwrites must be empty; rulepack `taint_semantics.clean_output_overwrite` populates this list",
    );
    assert!(
        config.source_output_args.is_empty(),
        "default source_output_args must be empty; rulepack source semantics populate this list",
    );
    assert!(
        config.source_callback_args.is_empty(),
        "default source_callback_args must be empty; rulepack source semantics populate this list",
    );
    assert!(
        config.call_result_passthroughs.is_empty(),
        "default call_result_passthroughs must be empty; rulepack transfer semantics populate this list",
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
