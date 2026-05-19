use super::{compute_flow_labels, sibling_suffix};

#[test]
fn sibling_suffix_rolls_over_past_z() {
    assert_eq!(sibling_suffix(0), "a");
    assert_eq!(sibling_suffix(25), "z");
    assert_eq!(sibling_suffix(26), "aa");
    assert_eq!(sibling_suffix(27), "ab");
    assert_eq!(sibling_suffix(51), "az");
    assert_eq!(sibling_suffix(52), "ba");
    assert_eq!(sibling_suffix(701), "zz");
    assert_eq!(sibling_suffix(702), "aaa");
}

fn chain(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_string()).collect()
}

#[test]
fn single_chain_gets_plain_number() {
    let labels = compute_flow_labels(&[chain(&["handle", "sink"])]);
    assert_eq!(labels, vec!["1"]);
}

#[test]
fn unrelated_chains_get_separate_numbers() {
    let labels = compute_flow_labels(&[chain(&["entry_a", "sink_x"]), chain(&["entry_b", "sink_y"])]);
    assert_eq!(labels, vec!["1", "2"]);
}

#[test]
fn same_entry_different_sink_is_not_a_split() {
    let labels = compute_flow_labels(&[chain(&["handle", "sink_x"]), chain(&["handle", "sink_y"])]);
    assert_eq!(labels, vec!["1", "2"]);
}

#[test]
fn same_entry_same_sink_via_different_path_is_a_split() {
    let labels = compute_flow_labels(&[
        chain(&["handle", "left", "sink"]),
        chain(&["handle", "right", "sink"]),
    ]);
    assert_eq!(labels, vec!["1a", "1b"]);
}

#[test]
fn three_way_split_gets_abc() {
    let labels = compute_flow_labels(&[
        chain(&["handle", "p1", "sink"]),
        chain(&["handle", "p2", "sink"]),
        chain(&["handle", "p3", "sink"]),
    ]);
    assert_eq!(labels, vec!["1a", "1b", "1c"]);
}

#[test]
fn mix_of_split_and_lone() {
    let labels = compute_flow_labels(&[
        chain(&["entry_a", "sink_x"]),
        chain(&["entry_b", "p1", "sink_y"]),
        chain(&["entry_b", "p2", "sink_y"]),
    ]);
    assert_eq!(labels, vec!["1", "2a", "2b"]);
}
