use super::*;

#[test]
fn complete_chain_mode_lifts_chain_caps() {
    let default_limits = ExportChainLimits::for_complete(false);
    let complete_limits = ExportChainLimits::for_complete(true);

    assert!(complete_limits.max_chains_per_target > default_limits.max_chains_per_target);
    assert!(complete_limits.max_entry_probes > default_limits.max_entry_probes);
    assert_eq!(complete_limits.max_chains_per_target, usize::MAX);
    assert_eq!(complete_limits.max_entry_probes, usize::MAX);
}

#[test]
fn complete_chain_mode_lifts_flow_label_caps() {
    let limits = ExportChainLimits::for_complete(true);
    let options = export_flow_label_options(true, limits);

    assert_eq!(options.max_chains, usize::MAX);
    assert_eq!(options.max_probes, usize::MAX);
    assert!(options.downstream_depth > FlowIdLabelOptions::default().downstream_depth);
    assert!(options.downstream_breadth > FlowIdLabelOptions::default().downstream_breadth);
    assert!(options.max_labels_per_func > FlowIdLabelOptions::default().max_labels_per_func);
    assert_eq!(options.downstream_depth, usize::MAX);
    assert_eq!(options.downstream_breadth, usize::MAX);
    assert_eq!(options.max_labels_per_func, usize::MAX);
}
