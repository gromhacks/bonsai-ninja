// Assignment-chain audit fixture (Rust).
use std::collections::HashMap;
use std::env;
use std::process::Command;

mod executor;

const CONST_OK: &str = "ls /tmp";

fn passthrough(x: String) -> String { x }
fn wrap(x: String) -> String { format!("wrapped:{}", x) }
fn combine(acc: String, item: &str) -> String { format!("{}:{}", acc, item) }

#[derive(Default)]
struct Bag { payload: String }

pub fn chain_simple() {
    // POSITIVE
    let tmp = env::var("CMD1").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(tmp).output();
}

pub fn chain_multi_hop() {
    // POSITIVE
    let t1 = env::var("CMD2").unwrap_or_default();
    let t2 = passthrough(t1);
    let t3 = wrap(t2);
    let t4 = passthrough(t3);
    let _ = Command::new("sh").arg("-c").arg(t4).output();
}

pub fn chain_branch_join(cond: bool) {
    // POSITIVE
    let t = if cond {
        env::var("CMD3").unwrap_or_default()
    } else {
        "safe-static".to_string()
    };
    let _ = Command::new("sh").arg("-c").arg(t).output();
}

pub fn chain_loop_carried(items: &[String]) {
    // POSITIVE
    let mut acc = env::var("CMD4").unwrap_or_default();
    for item in items {
        acc = combine(acc, item);
    }
    let _ = Command::new("sh").arg("-c").arg(acc).output();
}

pub fn chain_field_write() {
    // POSITIVE
    let mut bag = Bag::default();
    bag.payload = env::var("CMD5").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(bag.payload).output();
}

pub fn chain_subscript_write() {
    // POSITIVE
    let mut cmds: HashMap<String, String> = HashMap::new();
    cmds.insert("x".to_string(), env::var("CMD6").unwrap_or_default());
    let _ = Command::new("sh").arg("-c").arg(cmds.get("x").unwrap()).output();
}

pub fn chain_clean_constant() {
    // NEGATIVE
    let _unused = env::var("IGNORED").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(CONST_OK).output();
}

pub fn chain_cross_file() {
    // POSITIVE
    let t = env::var("CMD9").unwrap_or_default();
    executor::run_in_other_file(&t);
}
