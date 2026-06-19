use super::{compute_flow_labels, compute_taint_flow_id, sibling_suffix, TaintFlowIdentityStep};

#[derive(Clone)]
struct TestTaintStep {
    caller: &'static str,
    callee: &'static str,
    file: &'static str,
    line: u32,
    column: u32,
    args: Vec<(usize, &'static str, Option<&'static str>)>,
}

impl TaintFlowIdentityStep for TestTaintStep {
    fn caller(&self) -> &str {
        self.caller
    }

    fn callee(&self) -> &str {
        self.callee
    }

    fn file(&self) -> &str {
        self.file
    }

    fn line(&self) -> u32 {
        self.line
    }

    fn column(&self) -> u32 {
        self.column
    }

    fn for_each_tainted_arg(&self, visit: &mut dyn FnMut(usize, &str, Option<&str>)) {
        for (index, value, param) in &self.args {
            visit(*index, value, *param);
        }
    }
}

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

#[test]
fn taint_flow_id_is_deterministic_and_short() {
    let steps = vec![TestTaintStep {
        caller: "handle",
        callee: "sink",
        file: "app.py",
        line: 10,
        column: 4,
        args: vec![(0, "cmd", Some("command"))],
    }];

    let a = compute_taint_flow_id("handle", "os.system", &steps);
    let b = compute_taint_flow_id("handle", "os.system", &steps);

    assert_eq!(a, b);
    assert!(a.starts_with("T:"));
    assert_eq!(a.len(), 10);
    assert!(a[2..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn taint_flow_id_includes_locations_and_arg_evidence() {
    let base = vec![TestTaintStep {
        caller: "handle",
        callee: "sink",
        file: "app.py",
        line: 10,
        column: 4,
        args: vec![(0, "cmd", Some("command"))],
    }];
    let mut moved = base.clone();
    moved[0].line = 11;
    let mut changed_arg = base.clone();
    changed_arg[0].args = vec![(0, "safe", Some("command"))];

    assert_ne!(
        compute_taint_flow_id("handle", "os.system", &base),
        compute_taint_flow_id("handle", "os.system", &moved)
    );
    assert_ne!(
        compute_taint_flow_id("handle", "os.system", &base),
        compute_taint_flow_id("handle", "os.system", &changed_arg)
    );
}
